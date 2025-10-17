import mongoose from "mongoose";
import { user, Database, Order } from "../DB/model.js"; // Add Order import


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

const directPurchase = async (req, res) => {
    try {
        const { itemId, userId, quantity = 1, shippingAddress } = req.body;
        
        console.log("🔍 DirectPurchase Debug:");
        console.log("Request body:", req.body);
        console.log("userId:", userId);
        console.log("itemId:", itemId);
        console.log("userId type:", typeof userId);
        
        // Validate inputs
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            console.log("❌ No userId provided");
            return res.json({ success: false, message: "User ID is required" });
        }
        
    
        
        if (!mongoose.Types.ObjectId.isValid(itemId)) {
            console.log("❌ Invalid itemId format:", itemId);
            return res.json({ success: false, message: "Invalid product ID format" });
        }

        // Find user and product
        const userData = await user.findById(userId);
        if (!userData) {
            console.log("❌ User not found with ID:", userId);
            return res.json({ success: false, message: "User not found" });
        }
        
        const product = await Database.findById(itemId);
        if (!product) {
            console.log("❌ Product not found with ID:", itemId);
            return res.json({ success: false, message: "Product not found" });
        }

        console.log("✅ User found:", userData.email);
        console.log("✅ Product found:", product.productName);

        // Calculate purchase details
        const unitPrice = parseFloat(product.Price);
        const totalAmount = unitPrice * quantity;

        // Create new order
        const newOrder = new Order({
            orderId: `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
            userId: userId,
            productId: itemId,
            productName: product.productName,
            productImage: product.Image ? product.Image[0] : null,
            quantity: quantity,
            unitPrice: unitPrice,
            totalAmount: totalAmount,
            shippingAddress: shippingAddress || "To be provided at checkout",
            orderStatus: "confirmed",
            paymentStatus: "pending",
            estimatedDelivery: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        // Save the order
        await newOrder.save();

        console.log("✅ Order created successfully:", newOrder.orderId);

        // Return success with order details
        res.json({ 
            success: true, 
            message: "Direct purchase successful!", 
            order: {
                orderId: newOrder.orderId,
                productName: newOrder.productName,
                totalAmount: newOrder.totalAmount,
                orderStatus: newOrder.orderStatus,
                estimatedDelivery: newOrder.estimatedDelivery
            },
            productDetails: product
        });

    } catch (error) {
        console.error("❌ DirectPurchase Error:", error);
        res.status(500).json({ success: false, message: error.message });
    }
};

const getUserOrders = async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.json({ success: false, message: "Invalid userId" });
        }

        const userData = await user.findById(userId);
        if (!userData) return res.json({ success: false, message: "User not found" });

        const orders = userData.orders || [];
        
        res.json({ 
            success: true, 
            orders: orders.sort((a, b) => new Date(b.orderDate) - new Date(a.orderDate))
        });

    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};


export { addToCart, updateCart, getUserCart, deleteFromCart, directPurchase, getUserOrders };