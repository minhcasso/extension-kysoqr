/**
 * Cuộn `el` vào tầm nhìn chỉ bên trong `container`. Khác `scrollIntoView`: không cuộn các khung
 * cha (kể cả khung `overflow: hidden`), nên thanh header của trang xem không bị đẩy lên.
 */
export function scrollWithin(
  container: HTMLElement | null | undefined,
  el: Element | null | undefined,
  block: 'start' | 'center' | 'nearest',
  behavior: ScrollBehavior = 'auto',
) {
  if (!container || !el) return;
  const c = container.getBoundingClientRect();
  const r = el.getBoundingClientRect();
  const top = r.top - c.top + container.scrollTop;
  let next = container.scrollTop;
  if (block === 'start') next = top;
  else if (block === 'center') next = top - (container.clientHeight - r.height) / 2;
  else if (r.top < c.top) next = top;
  else if (r.bottom > c.bottom) next = top - container.clientHeight + r.height;
  else return;
  container.scrollTo({ top: next, behavior });
}
