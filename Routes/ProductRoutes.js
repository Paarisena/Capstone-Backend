import express from 'express';
import {addProduct,listProducts,deleteProduct, listPublicProducts, editProduct, addProfile, fetchProfile, sendEmail} from '../Login page/Dashboard.js';
import upload from '../Middleware/Multer.js';
import adminAuth from '../Middleware/adminAuth.js';
import { addToCart, updateCart,getUserCart, deleteFromCart } from '../Login page/CartModel.js';

const ProductRouter = express.Router();

ProductRouter.post('/addProducts',adminAuth,upload.fields([{name:'image1', maxCount:1},{name:'image2', maxCount:1},{name:'image3', maxCount:1},{name:'image4', maxCount:1}]), addProduct);
ProductRouter.get('/products',adminAuth, listProducts);
ProductRouter.put('/edit/:id',adminAuth, editProduct);
ProductRouter.get('/public-products', listPublicProducts);
ProductRouter.post('/profile',addProfile);
ProductRouter.get('/userProfile',fetchProfile);
ProductRouter.delete('/delete/:id',adminAuth, deleteProduct);
ProductRouter.post('/cart/add', addToCart);
ProductRouter.put('/cart/update/:itemId', updateCart);
ProductRouter.get('/cart', getUserCart);
ProductRouter.delete('/cart/delete/:itemId', deleteFromCart);
ProductRouter.post('/send-email', sendEmail);


export default ProductRouter;
