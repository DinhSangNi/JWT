const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema(
    {
        refreshToken: {
            type: String,
            require: true,
        }
    },
    { timestamps: true }
);

module.exports = mongoose.model("RefreshToken", refreshTokenSchema);
