// Draws a one-time-code field as one box per character, in the way of
// Bootstrap 6's OTP input: the real input stays the only field (one name,
// one value, autofill and paste untouched) and the boxes are decoration.
// Without this script the field still works as a spaced-out text input.
//
// Each box behaves on its own: typing replaces the box and moves on,
// deleting empties just that box. An empty box is a space in the value,
// so "12 456" draws 1, 2, an empty box, then 4, 5, 6.
const HOLE = " ";

for (const field of document.querySelectorAll("[data-code-field]")) {
  enhance(field);
}

function enhance(field) {
  const input = field.querySelector("input");
  const slots = [...field.querySelectorAll("[data-slot]")];
  const length = slots.length;
  const allowed = field.dataset.codeField === "alphanumeric" ? /[^0-9A-Z]/g : /[^0-9]/g;

  field.classList.add("is-live");
  // The pattern is for the field without this script; gaps are handled below.
  input.removeAttribute("pattern");

  // " 123-456 " pasted or autofilled keeps "123456"; letters are upper-cased.
  const clean = (text) => text.toUpperCase().replace(allowed, "").slice(0, length);

  const boxes = () => {
    const chars = [...input.value.slice(0, length)];
    while (chars.length < length) {
      chars.push(HOLE);
    }
    return chars;
  };

  const store = (chars, caret) => {
    input.value = chars.join("").trimEnd();
    const at = Math.max(0, Math.min(caret, input.value.length));
    input.setSelectionRange(at, at);
    render();
  };

  // The box the caret is on; the last box once the caret is past the end.
  const current = () => Math.min(input.selectionStart ?? 0, length - 1);

  const render = () => {
    const chars = boxes();
    const focused = document.activeElement === input;
    const active = current();

    slots.forEach((slot, index) => {
      slot.textContent = chars[index] === HOLE ? "" : chars[index];
      slot.classList.toggle("is-active", focused && index === active);
    });
  };

  input.addEventListener("beforeinput", (event) => {
    const chars = boxes();
    const at = current();

    if (event.inputType === "insertText" && event.data) {
      event.preventDefault();
      const typed = clean(event.data);
      [...typed].forEach((char, offset) => {
        if (at + offset < length) {
          chars[at + offset] = char;
        }
      });
      store(chars, at + typed.length);
    } else if (event.inputType === "deleteContentBackward") {
      event.preventDefault();
      const target = chars[at] !== HOLE ? at : at - 1;
      if (target >= 0) {
        chars[target] = HOLE;
        store(chars, target);
      }
    } else if (event.inputType === "deleteContentForward") {
      event.preventDefault();
      chars[at] = HOLE;
      store(chars, at);
    }
  });

  // Paste, autofill and undo arrive here and fill the boxes from the start.
  input.addEventListener("input", () => {
    const value = clean(input.value);
    store([...value], value.length);
  });

  // A drag or double-click would select several characters; keep only the
  // point where it started, so the highlighted box does not follow the pointer.
  const collapse = () => {
    const { selectionStart: start, selectionEnd: end, selectionDirection: direction } = input;
    if (start !== end) {
      const anchor = direction === "backward" ? end : start;
      input.setSelectionRange(anchor, anchor);
    }
  };

  // Browsers differ in which of these report a moved caret, so all of them do.
  const follow = () => {
    collapse();
    render();
  };
  for (const name of ["selectionchange", "click", "pointerup", "keyup", "select"]) {
    input.addEventListener(name, follow);
  }
  document.addEventListener("selectionchange", () => {
    if (document.activeElement === input) {
      follow();
    }
  });
  input.addEventListener("focus", () => requestAnimationFrame(render));
  input.addEventListener("blur", render);

  // An empty box anywhere means the code is not finished: go to it instead.
  input.form?.addEventListener("submit", (event) => {
    const empty = boxes().indexOf(HOLE);
    if (empty >= 0) {
      event.preventDefault();
      input.focus();
      input.setSelectionRange(empty, empty);
      render();
    }
  });

  input.value = clean(input.value);
  render();
}
