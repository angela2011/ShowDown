locals {
  prefix = "asm"

  images = {
    nginx  = "ghcr.io/${var.ghcr_owner}/asm-nginx:${var.image_tag}"
    api    = "ghcr.io/${var.ghcr_owner}/asm-api:${var.image_tag}"
    worker = "ghcr.io/${var.ghcr_owner}/asm-worker:${var.image_tag}"
  }

  # asyncpg takes ssl=require in the query string; Azure Postgres enforces TLS.
  database_url = "postgresql+asyncpg://asmadmin:${random_password.pg.result}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/asm?ssl=require"
  redis_url    = "redis://${azurerm_container_app.redis.name}:6379/0"
}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

# special=false keeps the password safe to embed in a URL without escaping
resource "random_password" "pg" {
  length  = 24
  special = false
}

resource "random_password" "api_secret" {
  length  = 32
  special = false
}

resource "azurerm_resource_group" "rg" {
  name     = "${local.prefix}-rg"
  location = var.location
}

# ---------- Logging (daily cap keeps ingestion costs bounded) ----------
resource "azurerm_log_analytics_workspace" "logs" {
  name                = "${local.prefix}-logs"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 0.5
}

resource "azurerm_container_app_environment" "env" {
  name                       = "${local.prefix}-env"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
}

# ---------- PostgreSQL (the one non-trivial fixed cost) ----------
resource "azurerm_postgresql_flexible_server" "pg" {
  name                = "${local.prefix}-pg-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  version                = "16"
  administrator_login    = "asmadmin"
  administrator_password = random_password.pg.result

  sku_name   = "B_Standard_B1ms"
  storage_mb = 32768

  backup_retention_days         = 7
  public_network_access_enabled = true

  lifecycle {
    ignore_changes = [zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "db" {
  name      = "asm"
  server_id = azurerm_postgresql_flexible_server.pg.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# 0.0.0.0-0.0.0.0 is Azure's special "allow Azure-internal services" rule.
# Trade-off: any Azure tenant could *attempt* to connect; they still need the
# password and TLS. Tighten with VNet integration once the app works.
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "AllowAzureServices"
  server_id        = azurerm_postgresql_flexible_server.pg.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# ---------- Redis as a small internal container (managed Azure Cache for Redis is closed to new customers) ----------
resource "azurerm_container_app" "redis" {
  name                         = "${local.prefix}-redis"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "redis"
      image  = "redis:7-alpine"
      cpu    = 0.25
      memory = "0.5Gi"
    }
  }

  ingress {
    external_enabled = false
    target_port      = 6379
    exposed_port     = 6379
    transport        = "tcp"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}

# ---------- API (internal only; reachable through the Nginx gateway) ----------
resource "azurerm_container_app" "api" {
  name                         = "${local.prefix}-api"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  secret {
    name  = "database-url"
    value = local.database_url
  }

  secret {
    name  = "api-secret"
    value = random_password.api_secret.result
  }

  template {
    min_replicas = 0
    max_replicas = 2

    container {
      name   = "api"
      image  = local.images.api
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name        = "API_SECRET_KEY"
        secret_name = "api-secret"
      }
      env {
        name  = "REDIS_URL"
        value = local.redis_url
      }
      env {
        name  = "SCAN_QUEUE_NAME"
        value = "scan_jobs"
      }
    }
  }

  ingress {
    external_enabled = false
    target_port      = 8000
    # Nginx talks to the API over plain HTTP inside the environment; without
    # this the ingress answers http:// with a redirect to https://.
    allow_insecure_connections = true

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  depends_on = [azurerm_postgresql_flexible_server_database.db, azurerm_postgresql_flexible_server_firewall_rule.azure_services]
}

# ---------- Worker (no ingress; pulls jobs from Redis) ----------
resource "azurerm_container_app" "worker" {
  name                         = "${local.prefix}-worker"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  secret {
    name  = "database-url"
    value = local.database_url
  }

  dynamic "secret" {
    for_each = var.slack_webhook_url == "" ? [] : [1]
    content {
      name  = "slack-webhook"
      value = var.slack_webhook_url
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "worker"
      image  = local.images.worker
      cpu    = 0.5
      memory = "1Gi"

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name  = "REDIS_URL"
        value = local.redis_url
      }
      env {
        name  = "SCAN_QUEUE_NAME"
        value = "scan_jobs"
      }

      dynamic "env" {
        for_each = var.slack_webhook_url == "" ? [] : [1]
        content {
          name        = "SLACK_WEBHOOK_URL"
          secret_name = "slack-webhook"
        }
      }
    }
  }

  depends_on = [azurerm_postgresql_flexible_server_database.db, azurerm_postgresql_flexible_server_firewall_rule.azure_services]
}

# ---------- Nginx gateway (the only public entry point) ----------
resource "azurerm_container_app" "gateway" {
  name                         = "${local.prefix}-gateway"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"

  template {
    min_replicas = 0
    max_replicas = 2

    container {
      name   = "nginx"
      image  = local.images.nginx
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "API_HOST"
        value = azurerm_container_app.api.ingress[0].fqdn
      }
      env {
        name  = "API_PORT"
        value = "80"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 80

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}
