import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{
        type:"string",
        required: true
    },
    email:{
        type:"string",
        required: true
    },
    password:{
        type:"string",
        required:true
    },
    // confirmpassword:{
    //     type:"string",
    //     required:true
    // }
   
})

const user = new mongoose.model("user", userSchema,"users" )

export {user}