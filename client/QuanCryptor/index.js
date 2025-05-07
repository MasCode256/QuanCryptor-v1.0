document.addEventListener("DOMContentLoaded", async () => {
  setTimeout(async () => {
    try {
      /* const is_user_has_account = await isUserHasAccount();

      if (is_user_has_account == "true") {
      } else {
      } */

      location.replace("login.html");
    } catch (error) {
      alert(error);
    }
  }, DELAY);
});
