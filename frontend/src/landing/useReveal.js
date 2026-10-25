import { useEffect } from "react";

/**
 * Fades in every [data-reveal] element inside `rootRef` as it scrolls into view.
 *
 * Elements are only hidden after this hook has "armed" the page (adds `lp-anim`).
 * If the visitor prefers reduced motion, or IntersectionObserver is missing,
 * nothing is ever hidden, so content can never get stuck invisible.
 */
export function useReveal(rootRef) {
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce || !("IntersectionObserver" in window)) return undefined;

    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.12 },
    );
    root.classList.add("lp-anim");
    root.querySelectorAll("[data-reveal]").forEach((el) => io.observe(el));
    return () => {
      io.disconnect();
      root.classList.remove("lp-anim");
    };
  }, [rootRef]);
}
