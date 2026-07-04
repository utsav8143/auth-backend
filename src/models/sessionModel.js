import mongoose from "mongoose";

const sessionSchema=new mongoose.Schema({
    user:{
        type:mongoose.Schema.Types.ObjectId,
        required:[true,"User is required"],
        ref:"user"

    },
    refreshTokenHashed:{
        type:String,
        required:[true,"Refresh token is required"]
    },
    ip:{
        type:String,
        required:true
    },
    userAgent:{
        type:String,
        required:true
    },
    revoked:{
        type:Boolean,
        required:false
    }},{
        timestamp:true

    }
)

const sessionModel=mongoose.model("Session",sessionSchema)

export default sessionModel;