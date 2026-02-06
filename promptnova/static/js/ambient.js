(() => {
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReduced) {
    document.querySelectorAll(".reveal").forEach((el) => el.classList.add("is-visible"));
    document.querySelectorAll("[data-count]").forEach((el) => {
      const target = Number(el.dataset.count || "0");
      const decimals = Number(el.dataset.decimals || (String(target).includes(".") ? 1 : 0));
      const suffix = el.dataset.suffix || "";
      el.textContent = `${target.toFixed(decimals)}${suffix}`;
    });
    return;
  }

  // Cursor glow + ring + trail
  const glow = document.createElement("div");
  glow.className = "cursor-glow";
  const ring = document.createElement("div");
  ring.className = "cursor-ring";
  document.body.appendChild(glow);
  document.body.appendChild(ring);

  const trailCount = 8;
  const trails = Array.from({ length: trailCount }, (_, index) => {
    const dot = document.createElement("div");
    dot.className = "cursor-trail";
    const baseOpacity = 0.45 - index * 0.04;
    dot.dataset.baseOpacity = String(baseOpacity);
    dot.style.opacity = String(baseOpacity);
    document.body.appendChild(dot);
    return dot;
  });

  let mouseX = window.innerWidth / 2;
  let mouseY = window.innerHeight / 2;
  let currentX = mouseX;
  let currentY = mouseY;
  let ringX = mouseX;
  let ringY = mouseY;
  const trailPositions = trails.map(() => ({ x: mouseX, y: mouseY }));

  window.addEventListener("mousemove", (event) => {
    mouseX = event.clientX;
    mouseY = event.clientY;
  });

  const animateGlow = () => {
    const dx = mouseX - currentX;
    const dy = mouseY - currentY;
    const speed = Math.min(Math.hypot(dx, dy), 120);

    currentX += dx * 0.12;
    currentY += dy * 0.12;
    ringX += (mouseX - ringX) * 0.22;
    ringY += (mouseY - ringY) * 0.22;

    const glowScale = 1 + speed / 240;
    glow.style.transform = `translate(${currentX - 260}px, ${currentY - 260}px) scale(${glowScale})`;

    const ringScale = 1 + speed / 320;
    ring.style.transform = `translate(${ringX - 27}px, ${ringY - 27}px) scale(${ringScale})`;

    let prevX = currentX;
    let prevY = currentY;
    trails.forEach((dot, index) => {
      const pos = trailPositions[index];
      pos.x += (prevX - pos.x) * 0.28;
      pos.y += (prevY - pos.y) * 0.28;
      const scale = Math.max(0.4, 1 - index * 0.08);
      dot.style.transform = `translate(${pos.x - 5}px, ${pos.y - 5}px) scale(${scale})`;
      prevX = pos.x;
      prevY = pos.y;
    });

    const rootStyle = document.documentElement.style;
    rootStyle.setProperty("--mouse-x", `${(currentX / window.innerWidth) * 100}%`);
    rootStyle.setProperty("--mouse-y", `${(currentY / window.innerHeight) * 100}%`);

    requestAnimationFrame(animateGlow);
  };
  requestAnimationFrame(animateGlow);

  const handleEnter = () => {
    glow.style.opacity = "0.7";
    ring.style.opacity = "1";
    trails.forEach((dot) => (dot.style.opacity = dot.dataset.baseOpacity || "0.4"));
  };
  const handleLeave = () => {
    glow.style.opacity = "0";
    ring.style.opacity = "0";
    trails.forEach((dot) => (dot.style.opacity = "0"));
  };
  window.addEventListener("mouseenter", handleEnter);
  window.addEventListener("mouseleave", handleLeave);

  // Reveal on scroll
  const revealItems = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.18 }
    );

    revealItems.forEach((item) => observer.observe(item));
  } else {
    revealItems.forEach((item) => item.classList.add("is-visible"));
  }

  // Count-up metrics
  const countItems = document.querySelectorAll("[data-count]");
  const animateCount = (el) => {
    if (el.dataset.counted) return;
    el.dataset.counted = "true";

    const target = Number(el.dataset.count || "0");
    const decimals = Number(el.dataset.decimals || (String(target).includes(".") ? 1 : 0));
    const suffix = el.dataset.suffix || "";
    const duration = 1200;
    const start = performance.now();

    const tick = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = target * eased;
      el.textContent = `${value.toFixed(decimals)}${suffix}`;
      if (progress < 1) {
        requestAnimationFrame(tick);
      }
    };

    requestAnimationFrame(tick);
  };

  if ("IntersectionObserver" in window) {
    const countObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            animateCount(entry.target);
            countObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.4 }
    );
    countItems.forEach((item) => countObserver.observe(item));
  } else {
    countItems.forEach((item) => animateCount(item));
  }

  // Tilt effect
  const tiltItems = document.querySelectorAll("[data-tilt]");
  tiltItems.forEach((item) => {
    const maxTilt = Number(item.dataset.tilt) || 8;

    const handleMove = (event) => {
      const rect = item.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const rotateX = ((y / rect.height) - 0.5) * -maxTilt;
      const rotateY = ((x / rect.width) - 0.5) * maxTilt;
      item.style.setProperty("--tilt-x", `${rotateX}deg`);
      item.style.setProperty("--tilt-y", `${rotateY}deg`);
      item.classList.add("tilt-active");
    };

    const handleLeave = () => {
      item.style.setProperty("--tilt-x", "0deg");
      item.style.setProperty("--tilt-y", "0deg");
      item.classList.remove("tilt-active");
    };

    item.addEventListener("mousemove", handleMove);
    item.addEventListener("mouseleave", handleLeave);
  });
})();
