const mongoose = require("mongoose")

const passwordReset = mongoose.Schema({
    user_id : {
        type: String,
        require : true,
        ref: "User"
    }, 
    email : {
        type : String,
        require : true
    }, 
    token : {
        type : String,
        require : false
    }
})

module.exports = mongoose.model("PasswordReset", passwordReset)