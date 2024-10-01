const User = require("../models/User");
const RefreshToken = require('../models/RefreshToken');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

let refreshTokens = [];

const authController = {
  //REGISTER
  registerUser: async (req, res) => {

    try {
      // check existing username
      const existingUsername = await User.findOne({ username: req.body.username });
      if (existingUsername) {
        return res.status(400).json({ message: 'username already exists !' });
      }

      // check existing email
      const existingEmail = await User.findOne({ email: req.body.email });
      if (existingEmail) {
        return res.status(400).json({ message: 'email already exists !' });
      }

      // encode password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);

      // create user
      const newUser = new User(
        {
          ...req.body,
          password: hashedPassword,
        }
      );

      // save to db
      const user = await newUser.save();
      return res.status(200).json(user);
    } catch (error) {
      return res.status(500).json(error);
    }

  },

  generateAccessToken: (user) => {
    return jwt.sign(
      {
        id: user.id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_ACCESS_KEY,
      { expiresIn: "15s" }
    );
  },

  generateRefreshToken: (user) => {
    return jwt.sign(
      {
        id: user.id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_REFRESH_KEY,
      { expiresIn: "7d" }
    );
  },


  sendMail: async ({ email, html }) => {

    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: 587,
      secure: false, // true for port 465, false for other ports
      auth: {
        user: process.env.EMAIL_NAME,
        pass: process.env.EMAIL_APP_PASSWORD,
      },
    });

    const info = await transporter.sendMail({
      from: '"Thương mại điện tử 👻" <no-reply@thuongmaidientu.com>', // sender address
      to: email, // list of receivers
      subject: "Hello ✔", // Subject line
      text: "Hello world?", // plain text body
      html: html, // html body
    });

    return info;
  },

  forgotPassword: async (req, res) => {

    try {
      // check missing email
      if (!req.body.email) {
        return res.status(400).json({ message: 'Missing email .' });
      }

      // check existing user
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(404).json({ succes: false, message: 'user not found .' });
      }

      const { email } = req.body;

      // create new token for link
      const newtoken = jwt.sign(
        {
          email
        },
        process.env.JWT_ACCESS_KEY,
        { expiresIn: "2h" }
      );

      // create html text
      const html = `Xin vui lòng click vào link dưới đây để thay đổi password của bạn. Link này sẽ hết hạn sau 15 phút kể từ bây giờ.
    <a href= ${process.env.URL_CLIENT}/resetpassword/${user._id}/${newtoken}>Click here</a>`;

      // send mail 
      const data = {
        email,
        html,
      }

      const rs = await authController.sendMail(data);
      return res.status(200).json({ success: true, rs });
    } catch (error) {
      return res.status(500).json({ message: 'internal error server .' });
    }
  },

  resetPassword: async (req, res) => {

    try {
      const id = req.params.id;
      const token = req.params.token;
      jwt.verify(token, process.env.JWT_ACCESS_KEY, (err, decodedInfo) => {
        if (err) {
          res.status(403).json({ success: false, message: "Token is expired ." });
        }
        else {
          if (!req.body.password) {
            return res.status(400).json({ message: 'Missing password' });
          }

          const updatePassword = async () => {
            try {
              const { password } = req.body;
              const salt = await bcrypt.genSalt(10);
              const hashedPassword = await bcrypt.hash(password, salt);
              const user = await User.findByIdAndUpdate({ _id: id }, { password: hashedPassword });
              return res.status(200).json({ success: true, user });
            } catch (error) {
              return res.status(500).json({ message: 'internal error server .' });
            }
          }

          updatePassword();
        }
      })

    } catch (error) {
      return res.status(500).json({ message: 'internal error server .' });
    }

  },

  //LOGIN
  loginUser: async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(404).json("Incorrect email");
      }
      const validPassword = await bcrypt.compare(
        req.body.password,
        user.password
      );
      if (!validPassword) {
        return res.status(404).json("Incorrect password");
      }
      if (user && validPassword) {
        //Generate access token
        const accessToken = authController.generateAccessToken(user);
        //Generate refresh token
        const refreshToken = authController.generateRefreshToken(user);
        // store new refresh token to DB
        const newRefreshToken = new RefreshToken({ refreshToken: refreshToken });
        await newRefreshToken.save();
        //STORE REFRESH TOKEN IN COOKIE
        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: false,
          path: "/",
          sameSite: "strict",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        const { password, ...others } = user._doc;
        return res.status(200).json({ ...others, accessToken, refreshToken });
      }
    } catch (err) {
      return res.status(500).json(err);
    }
  },

  requestRefreshToken: async (req, res) => {

    try {

      //Take refresh token from user
      const refreshToken = req.cookies.refreshToken;

      //Send error if token is not valid
      if (!refreshToken) return res.status(401).json("You're not authenticated");

      // check refresh token in db
      const existingRefreshToken = await RefreshToken.findOne({ refreshToken: refreshToken });
      if (!existingRefreshToken) {
        return res.status(403).json('Refresh token is not valid')
      }

      jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, async (err, user) => {
        if (err) {
          console.log(err);
        }

        // delete refresh token in db 
        await RefreshToken.deleteOne({ refreshToken: refreshToken });

        //create new access token, refresh token and send to user
        const newAccessToken = authController.generateAccessToken(user);
        const newRefreshToken = authController.generateRefreshToken(user);

        // push new refresh token to db
        const newRefreshTokenInDB = new RefreshToken({ refreshToken: newRefreshToken });
        await newRefreshTokenInDB.save();

        // send response
        res.cookie("refreshToken", newRefreshToken, {
          httpOnly: true,
          secure: false,
          path: "/",
          sameSite: "strict",
        });
        res.status(200).json({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        });
      });
    } catch (error) {

    }
  },

  //LOG OUT
  logOut: async (req, res) => {
    //Clear cookies when user logs out
    // refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
    try {
      await RefreshToken.deleteOne({ refreshToken: req.cookies.refreshToken });
      res.clearCookie("refreshToken");
      res.status(200).json("Logged out successfully!");
    } catch (error) {
      console.log(error);
    }
  },
};

module.exports = authController;
