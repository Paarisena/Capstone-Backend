import {Database} from '../DB/model.js'
import dotenv from 'dotenv'
import {v2 as cloudinary} from 'cloudinary'

dotenv.config()

const addProduct = async(req, res) =>{
    try{
        const {productName, productDescription, category, Price} = req.body
        if (!productName || !productDescription || !category || !Price) {
            return res.status(400).json({ message: "Missing required fields" });
        }
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).json({ message: "No files were uploaded" });
        }
        console.log('Request Body:', req.body);
        console.log('Request Files:', req.files);

        const image1 = req.files.image1 && req.files.image1[0]
        const image2 = req.files.image2 && req.files.image2[0]
        const image3 = req.files.image3 && req.files.image3[0]
        const image4 = req.files.image4 && req.files.image4[0]

        const images = [image1, image2, image3, image4].filter((item) => item !== undefined)

        
        const imageUrls = await Promise.all(images.map(async (item) =>{
            const result = await cloudinary.uploader.upload(item.path,{resource_type:"image"})
            return result.secure_url
        }))
        console.log(productName, productDescription, category, Price)
        console.log(imageUrls)

    const productData = new Database({
        productName,
        productDescription,
        category,
        Price,
        Image: imageUrls
    })

    console.log(productData)

    
    await productData.save()
    res.status(201).json({ message: "Product added successfully" });
} catch (err) {
    console.error('Error in Add Product',err); 
    res.status(500).json({ message: "Internal server error" });
}

}


const listProducts = async(req, res) =>{
    try{
        const products = await Database.find({})
        res.json({success:true,products})
    }catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
    }
}

const deleteProduct = async(req, res) =>{
    try{
        const {id} = req.params
        const deleteproducts = await Database.findByIdAndDelete(id)
         if (!deleteProduct) {
            return res.status(404).json({ success: false, message: "Product not found" });
         }
         res.json({success:true,deleteproducts})
    }catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
    }
}


const singleProduct = async(req, res) =>{
    try{
        const {id} = req.params
        const singleProduct = await Database.findById(id)
         if (!singleProduct) {
            return res.status(404).json({ success: false, message: "Product not found" });
         }
         res.json({success:true,singleProduct})
    }catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
    }
}   

const reviewProduct = async(req,res) =>{
    try{
        const {id} = req.params
        const {review} = req.body
        if (!review) {
            return res.status(400).json({ message: "Review is required" });
        }
        const product = await Database.findById(id)
        if (!product) {
            return res.status(404).json({ message: "Product not found" });
        }
        product.reviews.push(review)
        await product.save()
        res.json({success:true, message: "Review added successfully", product})
    } catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
}
}

export {addProduct,listProducts,deleteProduct, singleProduct, reviewProduct}
