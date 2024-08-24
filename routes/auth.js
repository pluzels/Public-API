require('../controllers/settings');
require('../controllers/message');

const express = require('express');
const router = express.Router();
const passport = require('passport');

// Lib
const {
   getHashedPassword,
   randomText
} = require('../lib/function');
const {
   checkEmail,
   checkUsername,
   addUser
} = require('../database/function');
const {
   notAuthenticated
} = require('../lib/auth');

router.get('/login', notAuthenticated, (req, res) => {
   res.render('login', {
      layout: 'login'
   });
});

router.post('/login', async (req, res, next) => {
   passport.authenticate('local', {
      successRedirect: '/dashboard',
      failureRedirect: '/login',
      failureFlash: `<div>
                  <span><b>Username or password not found</b></span>
                </div>`,
   })(req, res, next);
});

router.get('/signup', notAuthenticated, (req, res) => {
   res.render('signup', {
      layout: 'signup'
   });
});

router.post('/signup', async (req, res) => {
   try {
      let {
         email,
         username,
         password,
         password2
      } = req.body;

      // Validasi panjang password
      if (password.length < 6 || password2 < 6) {
         req.flash('error_msg', 'Password must contain at least 6 characters');
         return res.redirect('/signup');
      }

      // Validasi kecocokan password
      if (password === password2) {
         let checking = await checkUsername(username);
         let checkingEmail = await checkEmail(email);

         // Cek apakah email sudah digunakan
         if (checkingEmail) {
            req.flash('error_msg', 'A user with the same Email already exists');
            return res.redirect('/signup');
         }

         // Cek apakah username sudah digunakan
         if (checking) {
            req.flash('error_msg', 'A user with the same Username already exists');
            return res.redirect('/signup');
         } else {
            // Hash password dan buat API key
            let hashedPassword = getHashedPassword(password);
            let apikey = randomText(10);

            // Tambahkan user ke database
            addUser(username, email, hashedPassword, apikey);

            // Berikan pesan sukses dan arahkan ke login
            req.flash('success_msg', 'You are now registered and can log in');
            return res.redirect('/login');
         }
      } else {
         req.flash('error_msg', 'Password and Password confirmation are not the same');
         return res.redirect('/signup');
      }
   } catch (err) {
      console.log(err);
      req.flash('error_msg', 'Something went wrong. Please try again.');
      return res.redirect('/signup');
   }
});

router.get('/logout', (req, res) => {
   req.logout();
   req.flash('success_msg', 'Logout success');
   res.redirect('/login');
});

module.exports = router;