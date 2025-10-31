import express from 'express';
import {addProduct,listProducts,deleteProduct, listPublicProducts, editProduct, addProfile, fetchProfile, sendEmail} from '../Login page/Dashboard.js';
import upload from '../Middleware/Multer.js';
import adminAuth from '../Middleware/adminAuth.js';
import { addToCart, updateCart,getUserCart, deleteFromCart, directPurchase, getUserOrders } from '../Login page/CartModel.js';

const ProductRouter = express.Router();

ProductRouter.post('/addProducts',adminAuth,upload.fields([{name:'image1', maxCount:1},{name:'image2', maxCount:1},{name:'image3', maxCount:1},{name:'image4', maxCount:1}]), addProduct);
ProductRouter.get('/products',adminAuth, listProducts);
ProductRouter.put('/edit/:id',adminAuth, editProduct);
ProductRouter.get('/public-products', listPublicProducts);
ProductRouter.post('/profile',adminAuth,addProfile);
ProductRouter.get('/userProfile',adminAuth,fetchProfile);
ProductRouter.delete('/delete/:id',adminAuth, deleteProduct);
ProductRouter.post('/cart/add', adminAuth,addToCart);
ProductRouter.put('/cart/update/:itemId', adminAuth,updateCart);
ProductRouter.get('/cart',adminAuth, getUserCart);
ProductRouter.delete('/cart/delete/:itemId', adminAuth,deleteFromCart);
ProductRouter.post('/direct-purchase', adminAuth,directPurchase);
ProductRouter.get('/user-orders', adminAuth,getUserOrders);
ProductRouter.post('/send-email', adminAuth,sendEmail);


export default ProductRouter;
