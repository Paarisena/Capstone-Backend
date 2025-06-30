import jwt from "jsonwebtoken";

const adminAuth = (req, res, next) => {
    try{
        const {token} = req.headers
        if(!token){
            return res.json({message:"Unauthorized login"})
        } 
        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        if (token_decode !== process.env.ADMIN_EMAIL + process.env.ADMIN_PASSWORD) {
            return res.status.json({ message: "Unauthorized access" });
        }
     next()   
    }catch(error){
        console.log(error)
        return res.status(500).json({message:"Internal server error"})
    }
}
export default adminAuth