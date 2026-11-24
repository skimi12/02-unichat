const content = document.getElementById("content");
const counter = document.getElementById("charCount");
if (content && counter) {
  content.addEventListener("input", () => {
    const count = Array.from(content.value).length;
    counter.textContent = String(count);
    counter.classList.toggle("text-danger", count > 140);
  });
}
