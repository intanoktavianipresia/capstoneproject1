const CONFIG = {
  API_BASE_URL: "http://127.0.0.1:5000/api",
  TOKEN_KEY: "auth_token",
  USER_KEY: "user_data",
  ROLE_KEY: "user_role",
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = CONFIG;
}
