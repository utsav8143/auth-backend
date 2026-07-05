import mongoose from "mongoose";

const otpSchema=new mongoose.Schema({
    email:{
        type:String,
        required:[true,"Email is required"]
    },
    user:{
        type:mongoose.Schema.Types.ObjectId,
        required:[true,"Email is required"]
    },
    otpHashed:{
        type:String,
        required:[true,":OTP has is required"]
    }
},{timestamps:true})

const otpModel=mongoose.model("otps", otpSchema)

export default otpModel;