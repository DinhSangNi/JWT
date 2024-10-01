const User = require("../models/User");


const userControllers = {

    //get all users 
    getAllUsers: async (req, res) => {
        try {
            const users = await User.find();
            res.status(200).json(users);
        } catch (err) {
            res.status(500).json(err);
        }
    },

    // delete a user
    deleteUser: async (req, res) => {
        try {
            const user = await User.findById(req.params.id);
            if (user) {
                res.status(200).json("Deleted Succesfully");
            }
        } catch (err) {
            res.status(500).json(err);
        }
    }
}

module.exports = userControllers;