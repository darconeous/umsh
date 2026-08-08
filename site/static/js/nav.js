// Collapses the header navigation behind a button on narrow screens.
//
// The stylesheet only hides the navigation once this script has marked the
// document, so with scripting unavailable the links stay visible and wrap
// onto a second row rather than becoming unreachable.

(function () {
  var burger = document.querySelector(".nav-burger");
  var nav = document.getElementById("site-nav");
  if (!burger || !nav) return;

  document.documentElement.classList.add("has-nav-toggle");

  function setOpen(open) {
    burger.setAttribute("aria-expanded", open ? "true" : "false");
    nav.classList.toggle("is-open", open);
  }

  burger.addEventListener("click", function () {
    setOpen(burger.getAttribute("aria-expanded") !== "true");
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && burger.getAttribute("aria-expanded") === "true") {
      setOpen(false);
      burger.focus();
    }
  });

  document.addEventListener("click", function (event) {
    if (burger.getAttribute("aria-expanded") !== "true") return;
    if (burger.contains(event.target) || nav.contains(event.target)) return;
    setOpen(false);
  });

  // Coming back to a wide viewport leaves the panel state behind, so that
  // reopening at a narrow width starts closed rather than already open.
  window.addEventListener("resize", function () {
    if (window.innerWidth > 860) setOpen(false);
  });
})();
