const express = require('express');
const bodyParser = require('body-parser')
const router = express.Router();
const userController = require("../controllers/userController")
 
router.use(bodyParser.json())
router.use(bodyParser.urlencoded({ extended : true }))

router.get("/mail-verification", userController.mailVerfication);
router.get("/reset-password", userController.resetPassword);
router.post("/reset-password", userController.updatePassword);
router.get("/password-success", userController.resetPasswordSuccess);

module.exports = router 