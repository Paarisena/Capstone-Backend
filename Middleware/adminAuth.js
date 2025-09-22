import jwt from "jsonwebtoken";

import dotenv from "dotenv";
dotenv.config();

const adminAuth = (req, res, next) => {
    try {
        // Get token from Authorization header (Bearer <token>)
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Unauthorized login" });
        }
        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, process.env.SECRET_TOKEN);

        // Optionally, check for admin role or email
        // if (decoded.email !== process.env.ADMIN_EMAIL) {
        //     return res.status(403).json({ message: "Unauthorized access" });
        // }

        req.user = {id: decoded.id}; // Attach decoded user to request
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).json({ message: "Unauthorized login" });
    }
};

export default adminAuth;