import mongoose from "mongoose";
import { user, Database } from "../DB/model.js";


// add products to user cart
const addToCart = async (req, res) => {
    try {
        const { itemId, userId } = req.body;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.json({ success: false, message: "Invalid userId" });
        }

        const userData = await user.findById(userId);
        if (!userData) return res.json({ success: false, message: "User not found" });

        let cart = userData.cart || {};
        let itemIdStr = String(itemId);
        console.log("cart Add Keys", Object.keys(cart));
        console.log("itemId to add:", itemIdStr);
        cart[itemIdStr] = (cart[itemIdStr] || 0) + 1;

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
        const { itemId } = req.params;
        const { userId, quantity } = req.body;
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
        const { userId } = req.query;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.json({ success: false, message: "Invalid userId" });
        }

        const userData = await user.findById(userId);
        if (!userData) return res.status(404).json({ success: false, message: "User not found" });

        let cart = userData.cart || {};
        let cartDetails = {};

        // Fetch product details for each item in the cart
        for (const itemId of Object.keys(cart)) {
            if (!mongoose.Types.ObjectId.isValid(itemId)) continue;
            const product = await Database.findById(itemId); // <-- use Database here
            if (product) {
                cartDetails[itemId] = {
                    name: product.productName,
                    price: product.Price,
                    Image: product.Image,
                    quantity: cart[itemId]
                };
            }
        }

        res.json({ success: true, cart: cartDetails });
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

const deleteFromCart = async (req, res) => {
    
    try {
        const {itemId} = req.params
        const { userId } = req.body;
        if(!mongoose.Types.ObjectId.isValid(userId)){
            return res.json({ success: false, message: "Invalid userId" });
        }
        const userData = await user.findById(userId);
        if (!userData) {
            return res.json({ success: false, message: "User not found" });
        }
        let cart = userData.cart || {};
        const itemIdStr = String(itemId)
        console.log("Cart Keys", Object.keys(cart));
        console.log("itemId to delete:", itemIdStr);
        if (cart[itemIdStr]) {
            delete cart[itemIdStr];
            await user.findByIdAndUpdate(userId, { $set: { cart } });
            res.json({ success: true, message: "Item removed from cart" });
        } else {
            res.json({ success: false, message: "Item not found in cart" });
        }
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};


export { addToCart, updateCart, getUserCart, deleteFromCart };