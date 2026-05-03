import express from 'express';
import {addProduct,listProducts,deleteProduct, listPublicProducts, editProduct, addProfile, fetchProfile, sendEmail} from '../Login page/Dashboard.js';
import upload from '../Middleware/Multer.js';
import adminAuth from '../Middleware/adminAuth.js';
import userAuth from '../Middleware/userAuth.js';
import { addToCart, updateCart,getUserCart, deleteFromCart, directPurchase, getUserOrders } from '../Login page/CartModel.js';

const ProductRouter = express.Router();

// Admin-only routes
ProductRouter.post('/addProducts', adminAuth, upload.fields([{name:'image1', maxCount:1},{name:'image2', maxCount:1},{name:'image3', maxCount:1},{name:'image4', maxCount:1}]), addProduct);
ProductRouter.get('/products', adminAuth, listProducts);
ProductRouter.put('/edit/:id', adminAuth, editProduct);
ProductRouter.delete('/delete/:id', adminAuth, deleteProduct);
ProductRouter.post('/send-email', adminAuth, sendEmail);

// Public routes (no auth)
ProductRouter.get('/public-products', listPublicProducts);

// User routes
ProductRouter.post('/profile', userAuth, addProfile);
ProductRouter.get('/userProfile', userAuth, fetchProfile);
ProductRouter.post('/cart/add', userAuth, addToCart);
ProductRouter.put('/cart/update/:itemId', userAuth, updateCart);
ProductRouter.get('/cart', userAuth, getUserCart);
ProductRouter.delete('/cart/delete/:itemId', userAuth, deleteFromCart);
ProductRouter.post('/direct-purchase', userAuth, directPurchase);
ProductRouter.get('/user-orders', userAuth, getUserOrders);


export default ProductRouter;
