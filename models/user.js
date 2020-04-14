const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

// Create a schema
const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    }
});

userSchema.pre('save', async function(next) {
    try {
        // Generate a salt
        const salt = await bcrypt.genSalt(10);
        // Generate a password hash (salt + hash)
        const passwordHash = await bcrypt.hash(this.password, salt);
        // Re-assign hashed version over original, plain text password
        this.password = passwordHash;
        next();
    } catch (err) {
        next(err);
    }
});

userSchema.methods.isValidPassword = async function(newPassword) {
    try {
        return await bcrypt.compare(newPassword, this.password);
    } catch (err) {
        throw new Error(err);
    }
}

// Create a model
const User = mongoose.model('user', userSchema);

// Export the model
module.exports = User;