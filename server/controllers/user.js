const User = require('../models/user');
const mongoosHelpers = require('../helpers/mongoose');
const jwt = require('jsonwebtoken');
const config = require('../config/dev');

exports.auth = function(req,res){
    const{email,password} = req.body;
    if (!password|| !email) {
        return res.status(422).send({errors:[{title: 'data missing', detail: 'provide email and password'}]});
    }

    User.findOne({email}, function(err, user) {
       if (err) {
        return res.status(422).send({errors: mongoosHelpers.normalizeErrors(err.errors)});    
       }  

       if (!user) {
        return res.status(422).send({errors:[{title: 'invalid User', detail: 'User no exist'}]});
       }

       if (user.isSamePassword(password)) {
           const token = jwt.sign({ userId: user.id,
           username: user.username
         }, config.SECRET, { expiresIn: '1h' });

        return res.json(token) 
       }else {
        return res.status(422).send({errors:[{title: 'wrong data', detail: 'Wrong email or password'}]});
       }
    });
}

exports.register = function(req,res){
    const{username,email,password,passwordConfirmation} = req.body;

    if (!password|| !email) {
        return res.status(422).send({errors:[{title: 'data missing', detail: 'provide email and password'}]});
    }

    if (password !== passwordConfirmation) {
        return res.status(422).send({errors:[{title: 'invalid password', detail: 'password not same as confirmation'}]});
    }

    User.findOne({email: email}, function(err,existingUser){
        if (err) {
            return res.status(422).send({'mongoos': 'handle later'});    
        }
        if (existingUser) {
            return res.status(422).send({errors:[{title: 'invalid email', detail: 'email already exist.'}]});    
        }

        const user = new User({
            username,
            email,
            password
        });

        user.save(function(err){
            if (err) {
                return res.status(422).send({errors: mongoosHelpers.normalizeErrors(err.errors)});    
            }
            return res.json({'registerd':true});
        });
    });
}


exports.authMiddleware = function(req, res, next) {
    const token = req.headers.authorization;

    if (token) {
        const user = parseToken(token);

        User.findById(user.userId, function(err,user){
            if (err) {
                return res.status(422).send({errors: mongoosHelpers.normalizeErrors(err.errors)});    
            }

            if (user) {
                res.locals.user = user;
                next();
            }else {
                return notAuthorized(res);
            }
        });

    }else {
        return notAuthorized(res);
    }
}

function parseToken(token) {

    return jwt.verify(token.split(' ')[1], config.SECRET);
}

function notAuthorized(res) {
    return res.status(422).send({errors:[{title: 'not authed', detail: 'you need to login.'}]});   
}