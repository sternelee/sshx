/** Simple debounce utility, replacing lodash-es. */
export function debounce<T extends (...args: any[]) => void>(
  fn: T,
  ms: number,
): T & { cancel(): void } {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const wrapped = (...args: Parameters<T>) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn(...args);
    }, ms);
  };
  wrapped.cancel = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };
  return wrapped as T & { cancel(): void };
}

/** Simple throttle utility, replacing lodash-es. */
export function throttle<T extends (...args: any[]) => void>(
  fn: T,
  ms: number,
): T & { cancel(): void } {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let lastArgs: Parameters<T> | null = null;
  const wrapped = (...args: Parameters<T>) => {
    lastArgs = args;
    if (timer) return;
    fn(...args);
    timer = setTimeout(() => {
      timer = null;
      if (lastArgs) {
        const args = lastArgs;
        lastArgs = null;
        wrapped(...args);
      }
    }, ms);
  };
  wrapped.cancel = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    lastArgs = null;
  };
  return wrapped as T & { cancel(): void };
}
