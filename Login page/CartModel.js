import mongoose from "mongoose";
import { user } from "../DB/model.js";

// add products to user cart
const addToCart = async (req, res) => {
    try {
        const { userId, itemId } = req.body;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.json({ success: false, message: "Invalid userId" });
        }

        const userData = await user.findById(userId);
        if (!userData) return res.json({ success: false, message: "User not found" });

        let cart = userData.cart || {};
        cart[itemId] = (cart[itemId] || 0) + 1;

        await user.findByIdAndUpdate(userId, { $set: { cart } });

        res.json({ success: true, message: "Added To Cart" });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

// update user cart
const updateCart = async (req, res) => {
    try {
        const { userId, itemId, quantity } = req.body;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.json({ success: false, message: "Invalid userId" });
        }

        const userData = await user.findById(userId);
        if (!userData) return res.json({ success: false, message: "User not found" });

        let cart = userData.cart || {};
        cart[itemId] = quantity;

        await user.findByIdAndUpdate(userId, { $set: { cart } });
        res.json({ success: true, message: "Cart Updated" });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

// get user cart data
const getUserCart = async (req, res) => {
    try {
        const { userId } = req.body;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.json({ success: false, message: "Invalid userId" });
        }

        const userData = await user.findById(userId);
        if (!userData) return res.json({ success: false, message: "User not found" });

        let cart = userData.cart || {};
        res.json({ success: true, cart });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

export { addToCart, updateCart, getUserCart };