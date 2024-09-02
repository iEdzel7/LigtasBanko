function toggleMenu() {
  const menu = document.querySelector(".menu-links");
  const icon = document.querySelector(".hamburger-icon");
  menu.classList.toggle("open");
  icon.classList.toggle("open");
}

// Scroll to the top of the page just before it unloads
window.addEventListener('beforeunload', () => {
    window.scrollTo(0, 0);
});

document.addEventListener("DOMContentLoaded", () => {
  anime({
    targets: ".title1",
    opacity: [0, 1],
    scale: [0, 1],
    translateZ: [-500, 0],
    rotate: {
      value: 360,
      duration: 2000,
      easing: "easeInOutQuad",
    },
    duration: 2000,
    easing: "easeOutExpo",
    complete: () => {
      anime({
        targets: ".lg-img",
        translateY: [
          { value: -10, duration: 2000, easing: "easeInOutSine" },
          { value: 10, duration: 2000, easing: "easeInOutSine" },
        ],
        loop: true,
        direction: "alternate",
      });
    },
  });

  anime({
    targets: ".h1_style",
    opacity: [0, 1],
    translateY: [-20, 0],
    duration: 2000,
    easing: "easeOutExpo",
  });

  anime({
    targets: ".lg-img",
    opacity: [0, 1],
    scale: [0, 1],
    translateZ: [-500, 0],
    rotate: {
      value: 360,
      duration: 2000,
      easing: "easeInOutQuad",
    },
    duration: 2000,
    easing: "easeOutExpo",
    complete: () => {
      anime({
        targets: ".lg-img",
        translateY: [
          { value: -10, duration: 2000, easing: "easeInOutSine" },
          { value: 10, duration: 2000, easing: "easeInOutSine" },
        ],
        loop: true,
        direction: "alternate",
      });
    },
  });

  const floatingTargets = [
    ".phishing-1-icon",
    ".safe-1-icon",
    ".tools-img",
    ".contact-img",
    ".elvi-1-icon",
  ];

  floatingTargets.forEach((target) => {
    anime({
      targets: target,
      translateY: [
        { value: -10, duration: 2000, easing: "easeInOutSine" },
        { value: 0, duration: 2000, easing: "easeInOutSine" },
      ],
      loop: true,
    });
  });

  const submissionContainer = document.getElementById("submissionContainer");
  const optionsContainer = document.querySelector(".options-containerPhishingDetector");
  const options = optionsContainer.querySelectorAll(".option-labelPhishingDetector");
  const submissionButton = document.getElementById("submissionButton");
  const pasteURLDiv = document.getElementById("PasteURL");
  const screenshotDiv = document.getElementById("Screenshot");
  const messageDiv = document.getElementById("Message");
  const confidenceElements = document.querySelectorAll(".confidence");
  const completionElements = document.querySelectorAll(".completion");
  const Buttons = document.getElementById("rectangle-parent4");
  const ResultConfidence = document.getElementById("ResultAndConfidence");

  document.getElementById('screenshotUpload').addEventListener('change', function() {
    const filename = this.files[0].name;
    document.querySelector('.filename-placeholder').textContent = filename;
  });

  submissionContainer.addEventListener("click", (event) => {
    const isDisplayed = optionsContainer.style.display === "block";
    optionsContainer.style.display = isDisplayed ? "none" : "block";
    event.stopPropagation();
  });

  optionsContainer.addEventListener("click", (event) => {
    event.stopPropagation();
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("#submissionContainer")) {
      optionsContainer.style.display = "none";
    }
  });

  options.forEach((option) => {
    option.addEventListener("click", () => {
      const selectedValue = option.textContent;
      submissionButton.textContent = selectedValue;
      optionsContainer.style.display = "none";
      options.forEach((opt) => opt.classList.remove("selected"));
      option.classList.add("selected");

      const submissionMethod = selectedValue;
      fetch('/submission_method', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ submission_method: submissionMethod })
      }).then(response => {
        console.log(response);
      }).catch(error => {
        console.error('Error:', error);
      });

      if (selectedValue === "URL") {
        document.getElementById('urlInput').value = '';
        document.getElementById('msgInput').value = '';
        document.getElementById('results').innerHTML = '';
        pasteURLDiv.style.display = "block";
        screenshotDiv.style.display = "none";
        messageDiv.style.display = "none";
        if (Buttons.classList.contains("rectangle-parent4")) {
          Buttons.style.position = "relative";
          Buttons.style.top = "0px";
        }
      } else if (selectedValue === "Text Message") {
        document.getElementById('urlInput').value = '';
        document.getElementById('msgInput').value = '';
        document.getElementById('results').innerHTML = '';
        pasteURLDiv.style.display = "none";
        screenshotDiv.style.display = "none";
        messageDiv.style.display = "block";
        confidenceElements.forEach((element) => {
          element.style.top = "350px";
        });
        completionElements.forEach((element) => {
          element.style.top = "470px";
        });
        if (ResultConfidence) {
          ResultConfidence.style.position = "relative";
          ResultConfidence.style.top = "200px";
        }
        if (Buttons.classList.contains("rectangle-parent4")) {
          Buttons.style.position = "relative";
          Buttons.style.top = "100px";
        } else {
          Buttons.style.position = "initial";
          Buttons.style.top = "initial";
        }
      } else if (selectedValue === "Screenshot") {
        document.getElementById('urlInput').value = '';
        document.getElementById('msgInput').value = '';
        document.getElementById('results').innerHTML = '';
        pasteURLDiv.style.display = "none";
        screenshotDiv.style.display = "block";
        messageDiv.style.display = "none";
        if (Buttons.classList.contains("rectangle-parent4")) {
          Buttons.style.position = "relative";
          Buttons.style.top = "0px";
        }
        confidenceElements.forEach((element) => {
          element.style.top = "300px";
        });
        completionElements.forEach((element) => {
          element.style.top = "520px";
        });
      }
    });
  });

  document.getElementById('clearBtn').addEventListener('click', () => {
    document.getElementById('urlInput').value = '';
    document.getElementById('msgInput').value = '';
    document.querySelector('.filename-placeholder').textContent = 'Upload Screenshot (jpeg/jpg/png)';
    document.getElementById('results').innerHTML = '';
  });
});

const nameInput = document.getElementById("nameInput");
const emailInput = document.getElementById("emailInput");
const subjectButton = document.getElementById("subjectButton");
const messageInput = document.getElementById("messageInput");
const submitButton = document.querySelector(".submit-button");
const urlInput = document.getElementById("urlInput");

const optionsContainer = document.querySelector(".options-container");

subjectButton.addEventListener("click", (event) => {
  event.preventDefault();
  optionsContainer.style.display =
    optionsContainer.style.display === "none" ? "block" : "none";
});

const options = optionsContainer.querySelectorAll(".option-label");

options.forEach((option) => {
  option.addEventListener("click", () => {
    const selectedValue = option.textContent;
    subjectButton.textContent = selectedValue;
    subjectButton.setAttribute("data-selected-value", selectedValue);
    optionsContainer.style.display = "none";
    options.forEach((opt) => opt.classList.remove("selected"));
    option.classList.add("selected");
  });
});

document.addEventListener("click", (event) => {
  if (!event.target.closest("#subjectButton")) {
    optionsContainer.style.display = "none";
  }
});

document
  .getElementById("contact-us")
  .addEventListener("submit", function (event) {
    event.preventDefault();
    if (!validateInputs()) {
      return;
    }
    submitForm();
  });

function validateInputs() {
  if (nameInput.value.trim() === "") {
    alert("Please enter your name.");
    return false;
  }
  if (emailInput.value.trim() === "") {
    alert("Please enter your email address.");
    return false;
  }
  if (!subjectButton.getAttribute("data-selected-value")) {
    alert("Please select a subject for your inquiry.");
    return false;
  }
  if (messageInput.value.trim() === "") {
    alert("Please enter your message.");
    return false;
  }
  return true;
}

function submitForm() {
  submitButton.disabled = true;

  fetch("/submit_form", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: nameInput.value,
      email: emailInput.value,
      subject: subjectButton.getAttribute("data-selected-value"),
      message: messageInput.value,
    }),
  })
    .then((response) => {
      if (response.ok) {
        alert("Form submitted successfully!");
        nameInput.value = "";
        emailInput.value = "";
        subjectButton.textContent = "Subject";
        subjectButton.removeAttribute("data-selected-value");
        messageInput.value = "";
      } else {
        throw new Error("Form submission failed.");
      }
    })
    .catch((error) => {
      alert("There was an error submitting the form. Please try again.");
      console.error("Form submission error:", error);
    })
    .finally(() => {
      submitButton.disabled = false;
    });
}
