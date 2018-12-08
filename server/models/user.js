const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: {
        type: String,
        min: [4,'min 4 chars'],
        max:[32, 'max 32 Chars']
    },
    email: {
        type: String,
        min: [4,'min 4 chars'],
        max:[32, 'max 32 Chars'],
        unique: true,
        lowercase: true,
        required: 'Email required',
        match:[/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/]
    },
    password: {
        type: String,
        min: [4,'min 4 chars'],
        max:[32, 'max 32 Chars'],
        required: 'pass required'
    },
    rentals: [{type: Schema.Types.ObjectId, ref: 'Rental'} ]
});

userSchema.methods.isSamePassword = function(requestedPassword) {

    return bcrypt.compareSync(requestedPassword, this.password);
    
}

userSchema.pre('save', function(next) {
    const user = this;

    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(user.password, salt, function(err, hash) {
            user.password = hash;
            next();
        });
    });
});

module.exports = mongoose.model('User', userSchema);
