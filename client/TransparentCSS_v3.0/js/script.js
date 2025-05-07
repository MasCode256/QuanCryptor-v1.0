(function (global) {
  const TEXT_COLOR = "var(--text-color)";
  const SECOND = 1000;

  const MAIN_DELAY = 1 * SECOND;
  const DISPLAYING_DELAY = 2 * SECOND;

  const TRANSITION_MULTIPLIER = 3.5;
  let transition = 0.3 * SECOND;
  let long_transition = transition * TRANSITION_MULTIPLIER;

  function handleError(err) {
    alert(
      `Критическая ошибка JavaScript: ${err}. Приложение будет перезагружено.`
    );

    if (pywebview) {
      pywebview.api.show_error(err);
    } else {
      console.error(err);
    }

    global.location.replace(global.location.href());
  }

  function print(message) {
    try {
      if (pywebview) {
        pywebview.api.show_message(message);
      } else {
        console.log(message);
      }
    } catch (error) {
      handleError(`${error}`);
    }
  }

  function getRandomInRange(min, max) {
    return Math.floor(Math.random() * (max - min)) + min; // Возвращаем целое число
  }

  async function list_files_in_dir(dir_path) {
    try {
      const response = await pywebview.api.list_files_in_dir(dir_path);
      return response;
    } catch (error) {
      handleError(`${error}`);
      return null;
    }
  }

  async function set_background_image() {
    let _list_files_in_dir;
    try {
      _list_files_in_dir = await list_files_in_dir(
        `${TransparentCSS.version}/images`
      );
    } catch (error) {
      handleError(error);
      TransparentCSS.log({}, "JavaScript error:", error);
    }

    if (!_list_files_in_dir || _list_files_in_dir == null) {
      TransparentCSS.log(
        {},
        "JavaScript error:",
        "cannot get background image."
      );
      throw new Error("Cannot get list of images");
    } else {
      let image =
        _list_files_in_dir[getRandomInRange(0, _list_files_in_dir.length)];

      global.document.body.style.setProperty(
        "background-image",
        `url('${TransparentCSS.version}/images/${image}')`
      );
    }
  }

  const BACKGROUND_OVERLAPPER_ID = "_background_overlapper";
  var background_overlapper = global.document.getElementById(
    BACKGROUND_OVERLAPPER_ID
  );

  function create_background_overlapper() {
    if (!global.document.contains(background_overlapper)) {
      let new_background_overlapper = global.document.createElement("div");
      new_background_overlapper.id = BACKGROUND_OVERLAPPER_ID;
      global.document.body.appendChild(new_background_overlapper);

      background_overlapper = global.document.getElementById(
        BACKGROUND_OVERLAPPER_ID
      );
    }
  }

  function display_document() {
    global.document.body.classList.add("animated");

    setTimeout(() => {
      global.document.body.style.setProperty("overflow", "auto");
    }, 2000);
  }

  function prepare_descriptions() {
    let elements = global.document.querySelectorAll(
      ".element-with-description"
    );
    let description_span = global.document.createElement("span");
    description_span.classList.add("element-description");
    global.document.body.appendChild(description_span); // Добавляем span один раз

    elements.forEach(function (element) {
      let timeout = 0;
      let interval = 0;

      element.addEventListener("mouseover", function () {
        const description = element.getAttribute("data-description");
        if (description) {
          description_span.style.setProperty("opacity", "1");
          description_span.innerHTML = ""; // Очищаем предыдущий текст
          let i = 0;

          const addCharacter = () => {
            if (i < description.length) {
              description_span.innerHTML += description[i++];
              requestAnimationFrame(addCharacter); // Используем requestAnimationFrame для плавной анимации
            }
          };

          timeout = setTimeout(() => {
            addCharacter();
          }, 250);
        } else {
          description_span.style.setProperty("opacity", "0");
          print(
            `[Warning] Element with id '${element.id}' has class '.element-with-description', but does not have attribute 'data-description'.`
          );
        }
      });

      element.addEventListener("mouseout", function () {
        description_span.style.setProperty("opacity", "0");
        clearTimeout(timeout);
        clearInterval(interval);
        setTimeout(() => {
          description_span.innerHTML = ""; // Очищаем текст при уходе мыши
        }, 200);
      });
    });
  }

  function prepare_descriptions_2() {
    let elements = global.document.querySelectorAll(
      ".element-with-description"
    );

    elements.forEach(function (element) {
      let timeout = 0;
      let interval = 0;
      let description_span = global.document.createElement("span");

      description_span.classList.add("element-description");

      element.addEventListener("mouseover", function () {
        if (element.getAttribute("data-description")) {
          description_span.style.setProperty("opacity", "1");
          timeout = setTimeout(function () {
            global.document.body.appendChild(description_span);

            let i = 0;
            let text = element.getAttribute("data-description");

            interval = setInterval(function () {
              description_span.innerHTML += text[i];

              i++;
              if (i >= text.length) {
                clearInterval(interval);
              }
            }, 10);
          }, 1000);
        } else {
          description_span.remove();
          TransparentCSS.log(
            {},
            `[Warning] Element with id '${element.id}' have class '.element-with-description', but not have attribute 'data-description'.`
          );
        }
      });

      element.addEventListener("mouseout", function () {
        description_span.style.setProperty("opacity", "0");

        setTimeout(function () {
          description_span.innerHTML = "";

          clearTimeout(timeout);
          clearInterval(interval);
          description_span.remove();
        }, 300);
      });
    });
  }

  function handle_mouse_coordinates() {
    window.addEventListener("mousemove", function (event) {
      let x = event.clientX;
      let y = event.clientY;

      global.document.documentElement.style.setProperty("--mouse-x", `${x}px`);
      global.document.documentElement.style.setProperty("--mouse-y", `${y}px`);
    });
  }

  var console_div = document.getElementById("console");

  function create_console_element() {
    if (!document.contains(console_div)) {
      let new_console_div = document.createElement("div");
      new_console_div.id = "console";
      global.document.body.appendChild(new_console_div);

      console_div = document.getElementById("console");
    }
  }

  const ALWAYS_VISIBLE_CLASS = "always-visible";

  function animate_loading() {
    //TransparentCSS.log({}, "[Animating loading 0/X] Creating elements...");

    let video = global.document.createElement("video");
    let source = global.document.createElement("source");

    video.classList.add(ALWAYS_VISIBLE_CLASS);
    video.id = "loading-animation";

    //TransparentCSS.log({}, "[Animating loading 1/X] Setting sources...");

    source.src = `${TransparentCSS.version}/videos/loading.mp4`;
    source.type = "video/mp4";

    //TransparentCSS.log({}, "[Animating loading 2/X] Adding sources...");

    video.appendChild(source);

    video.innerHTML += "Loading...";

    /*TransparentCSS.log(
      {},
      `[Animating loading (debug)] video.innerHTML: ${video.innerHTML}`
    );*/

    video.load();

    global.document.body.appendChild(video);

    video.play();

    setTimeout(() => {
      video.classList.add("animated");

      setTimeout(() => {
        video.remove();
      }, long_transition + 1);
    }, DISPLAYING_DELAY + 1);
  }

  function datetime() {
    const now = new Date();
    const month = now.getMonth() + 1; // Получение месяца (от 0 до 11, поэтому +1)
    const day = now.getDate(); // Получение дня
    const hours = now.getHours(); // Получение часов
    const minutes = now.getMinutes(); // Получение минут
    const seconds = now.getSeconds(); // Получение секунд

    return `${parseInt(day) > 9 ? day : `0${day}`}.${
      parseInt(month) > 9 ? month : `0${month}`
    } ${parseInt(hours) > 9 ? hours : `0${hours}`}:${
      parseInt(minutes) > 9 ? minutes : `0${minutes}`
    }:${parseInt(seconds) > 9 ? seconds : `0${seconds}`}`;
  }

  const TransparentCSS = {
    log: function (
      {
        color = TEXT_COLOR,
        opacity = 1,
        delimiter = " ",
        hiding_timeout = 15 * SECOND,
        delay = 600,
      } = {},
      ...data
    ) {
      try {
        let text = "";
        let dt = `[ ${datetime()} ]`;

        data.forEach((str, index) => {
          text += (index > 0 ? delimiter : "") + str;
        });

        print(text);

        let time = global.document.createElement("span");
        time.style.setProperty("opacity", opacity / 2);
        time.classList.add("time");

        let line = global.document.createElement("span");
        line.style.setProperty("opacity", opacity);
        line.style.setProperty("color", color);
        line.classList.add("line");

        let p = global.document.createElement("p");
        p.classList.add("hided", "size-0");
        p.appendChild(time);
        p.appendChild(line);

        console_div.appendChild(p);

        const DELAY = delay / (text.length + dt.length);

        for (let index = 0; index < dt.length; index++) {
          setTimeout(() => {
            time.innerHTML += dt[index];
          }, DELAY * index);
        }

        for (let index = 0; index < text.length; index++) {
          setTimeout(() => {
            line.innerHTML += text[index];
          }, DELAY * (index + dt.length));
        }

        setTimeout(() => {
          p.classList.remove("hided", "size-0");
        }, 10);

        setTimeout(() => {
          p.classList.add("hided");

          setTimeout(() => {
            p.remove();
          }, 1000);
        }, hiding_timeout + (text.length + dt.length) * DELAY);
      } catch (err) {
        handleError(`[TransparentCSS.log()] ${err}`);
      }
    },
    handleErr: function (err) {
      TransparentCSS.log(
        {
          color: "var(--error)",
          hiding_timeout: 25 * SECOND,
        },
        err
      );

      handleError(err);
    },

    setTransition: function (new_transition = transition) {
      global.document.documentElement.style.setProperty("--tt", new_transition);
      long_transition = new_transition * TRANSITION_MULTIPLIER;
      transition = new_transition;
    },
    getTransition: function () {
      return transition;
    },

    version: "TransparentCSS_v3.0",
  };

  function main() {
    try {
      create_background_overlapper();
      handle_mouse_coordinates();
      create_console_element();
      prepare_descriptions();
      animate_loading();
    } catch (err) {
      handleError(`${err}`);
    }

    setTimeout(async () => {
      try {
        set_background_image();
        display_document();
      } catch (err) {
        handleError(`${err}`);
      }
    }, DISPLAYING_DELAY);
  }

  global.document.addEventListener("DOMContentLoaded", async () => {
    setTimeout(() => {
      try {
        main();
      } catch (error) {
        alert(error);
      }
    }, MAIN_DELAY);
  });

  // Экспортируем библиотеку в глобальную область видимости
  global.TransparentCSS = TransparentCSS;
})(this);
