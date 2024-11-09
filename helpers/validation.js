const { check } = require("express-validator")

exports.registerValidator = [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Email is required').isEmail().normalizeEmail({
        gmail_remove_dots : true
    }),
    check('mobile', 'Mobile number should be contain 10 digit').isLength({
        min : 0,
        max : 10
    }),
    check('password', 'Password must greater than 6 characters, and contain atleast upper case letter, atleast one lowercase letter, and min one number, and one special character').isStrongPassword({
        minLength : 6,
        minUppercase : 1,
        minLowercase : 1, 
        minNumbers : 1,
        minSymbols : 1
    }),
    check('image').custom( (value, {req})=> {
        if(req.file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
            return true;
        } else {
            return true;
        }
    }).withMessage('Please upload image jpeg and png')
];

exports.sendVerificationMail = [
    check('email', 'Email is required').isEmail().normalizeEmail({
        gmail_remove_dots : true
    })
];

exports.loginValidator = [
    check('email', 'Email is required').isEmail().normalizeEmail({
        gmail_remove_dots : true
    }),
    check('password', 'Password is required').not().isEmpty(),
];
 
exports.updateProfileValidator = [
    check('name', 'Name is required').not().isEmpty(),
    check('mobile', 'Mobile number should contain 10 digits').isLength({ 
        min: 10, 
        max: 10 
    })
];