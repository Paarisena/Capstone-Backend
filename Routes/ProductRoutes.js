import express from 'express';
import {addProduct,listProducts,deleteProduct} from '../Login page/Dashboard.js';
import upload from '../Middleware/Multer.js';
import adminAuth from '../Middleware/adminAuth.js';
import { addToCart, updateCart,getUserCart } from '../Login page/CartModel.js';

const ProductRouter = express.Router();

ProductRouter.post('/addProducts',upload.fields([{name:'image1', maxCount:1},{name:'image2', maxCount:1},{name:'image3', maxCount:1},{name:'image4', maxCount:1}]), addProduct);
ProductRouter.get('/products', listProducts);
ProductRouter.delete('/delete/:id', deleteProduct);
ProductRouter.post('/cart/add', addToCart);
ProductRouter.put('/cart/update', updateCart);
ProductRouter.get('/cart', getUserCart);

export default ProductRouter;