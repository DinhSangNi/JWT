const authController = require("../controllers/authController");

const router = require("express").Router();
const { verifyToken } = require("../controllers/verifyToken");

//REGISTER
router.post("/register", authController.registerUser);

//REFRESH TOKEN
router.post("/refresh", authController.requestRefreshToken);
//LOG IN
router.post("/login", authController.loginUser);
//LOG OUT
router.post("/logout", verifyToken, authController.logOut);
// Exit test 
router.post("/exit", authController.logOut);
// FORGOT PASSWORD
router.post("/forgotpassword", authController.forgotPassword);
// RESET PASSWORD 
router.post("/resetpassword/:id/:token", authController.resetPassword);

module.exports = router;