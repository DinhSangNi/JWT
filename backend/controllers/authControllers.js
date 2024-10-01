const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");

let refreshTokens = [];

const authControllers = {


    registerUser: async (req, res) => {
        try {

            //hash the user's password
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(req.body.password, salt);

            //create a user 
            const newUser = new User({
                username: req.body.username,
                email: req.body.email,
                password: hashed,
            })

            // save new user to DB
            const user = await newUser.save();
            res.status(200).json(user);
        } catch (err) {
            res.status(500).json(err);
        }
    },

    generateAccessToken: (user) => {
        return jwt.sign({
            id: user.id,
            admin: user.admin,
        },
            process.env.JWT_ACCESS_KEY,
            { expiresIn: "20s" }
        )
    },

    generateRefreshToken: (user) => {
        return jwt.sign(
            {
                id: user.id,
                admin: user.admin,
            },
            process.env.JWT_REFRESH_KEY,
            { expiresIn: "365d" }
        )
    },

    // login
    loginUser: async (req, res) => {
        try {
            const user = await User.findOne({ username: req.body.username });
            if (!user) {
                res.status(404).json("Wrong username");
            }
            const validPassword = await bcrypt.compare(req.body.password, user.password);
            if (!validPassword) {
                res.status(404).json("Wrong password");
            }
            if (user && validPassword) {
                // create a access token 
                const accessToken = authControllers.generateAccessToken(user);
                // Create a refresh token
                const refreshToken = authControllers.generateRefreshToken(user);
                // store refresh token to cookie
                res.cookie("refreshToken", refreshToken, {
                    httpOnly: true,
                    secure: false,
                    path: "/",
                    samesite: "strict",

                });
                refreshTokens.push(refreshToken);
                const { password, ...others } = user._doc;
                res.status(200).json({ ...others, accessToken });
            }
        } catch (err) {
            res.status(500).json(err);
        }
    },

    //request refresh token
    requestRefreshToken: async (req, res) => {
        try {
            const refreshToken = req.cookies.refreshToken;
            if (!refreshToken) {
                res.status(401).json("You're not authenticated");
            }
            if (!refreshTokens.includes(refreshToken)) {
                res.status(401).json("Token is not valid");
            }
            jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
                if (err) {
                    res.status(401).json(err);
                }

                refreshTokens = refreshTokens.filter((token) => { token !== refreshToken });
                // create a new access token
                const newAccessToken = authControllers.generateAccessToken(user);
                // create a new refresh token
                const newRefreshToken = authControllers.generateRefreshToken(user);
                refreshTokens.push(newRefreshToken);
                // store new refresh token to cookie
                res.cookie("refreshToken", newRefreshToken, {
                    httpOnly: true,
                    secure: false,
                    path: "/",
                    samesite: "strict",
                });
                res.status(200).json({ accessToken: newAccessToken });
            })
        } catch (err) {
            res.status(500).json(err);
        }
    },

    // user logout
    logout: async (req, res) => {
        res.clearCookie("refreshToken");
        refreshTokens = refreshTokens.filter((token) => { token !== req.cookies.refreshToken });
        res.status(200).json("Logged out");
    }

}

module.exports = authControllers;