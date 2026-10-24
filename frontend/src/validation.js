import {utcDate} from './data.js';
export function validateDomains(value){
 if(!Array.isArray(value)||value.some(d=>!d||typeof d.id!=='string'||typeof d.name!=='string'||typeof d.verified!=='boolean'))throw new Error('Invalid domains response; no live data has been substituted.');return value;
}
export function validateScans(value,domainId){
 if(!Array.isArray(value)||value.some(s=>!s||typeof s.id!=='string'||s.domain_id!==domainId||!['queued','running','completed','failed'].includes(s.status)||!Number.isFinite(utcDate(s.created_at).getTime())))throw new Error('Invalid scan-history response; this domain is excluded from the partial snapshot.');return value;
}
