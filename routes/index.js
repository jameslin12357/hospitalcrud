var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var { body,validationResult } = require('express-validator/check');
var { sanitizeBody } = require('express-validator/filter');
var bcrypt = require('bcryptjs');
var saltRounds = 10;
var moment = require('moment');
var mysql = require('mysql');

// Middlewares
function isNotAuthenticated(req, res, next) {
    if (!(req.isAuthenticated())){
        return next();
    }
    res.redirect('/403');
}

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect('/login');
}

// extract word after first slash and word after second slash
function isResource(req, res, next) {
    let uri = req._parsedOriginalUrl.path;
    if (uri.includes('/api')){
        uri = uri.substring(4);
    }
    if (uri.includes('?')){
        uri = uri.substring(0, uri.indexOf("?"));
    }
    uri = uri.substring(1);
    uri = uri.substring(0, uri.indexOf('/'));
    // let table = uri.substring(0, uri.length - 1);
    let table = uri;
    let id = Number(req.params.id);
    let connection = mysql.createConnection({
        host     : process.env.DB_HOSTNAME,
        user     : process.env.DB_USERNAME,
        password : process.env.DB_PASSWORD,
        port     : process.env.DB_PORT,
        database : process.env.DB_NAME,
        multipleStatements: true
    });
    connection.query('SELECT id FROM ' + table + ' WHERE id = ?', [id], function(error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        if (results.length === 0){
            res.render('404');
        }
        else {
            next();
        }
    });
}

// function isOwnResource(req, res, next) {
//     let uri = req._parsedOriginalUrl.path;
//     uri = uri.substring(1);
//     uri = uri.substring(0, uri.lastIndexOf('/'));
//     if (uri.includes('/')){
//         uri = uri.substring(0, uri.lastIndexOf('/'));
//     }
//     uri = uri.substring(0, uri.length - 1);
//     let table = uri;
//     let resourceid = req.params.id;
//     if (table === 'user') {
//         if (req.user.id !== Number(resourceid)) {
//             res.render('403');
//         } else {
//             next();
//         }
//     } else {
//         var connection = mysql.createConnection({
//             host     : process.env.DB_HOSTNAME,
//             user     : process.env.DB_USERNAME,
//             password : process.env.DB_PASSWORD,
//             port     : process.env.DB_PORT,
//             database : process.env.DB_NAME,
//             multipleStatements: true
//         });
//         connection.query('SELECT userid FROM ' + table + ' WHERE id = ?', [resourceid], function (error, results, fields) {
//             // error will be an Error if one occurred during the query
//             // results will contain the results of the query
//             // fields will contain information about the returned results fields (if any)
//             if (error) {
//                 throw error;
//             }
//             if (req.user.id !== results[0].userid) {
//                 res.render('403');
//             } else {
//                 next();
//             }
//         });
//     }
// }

/* GET home page. */
// if user is logged in return feed page else return home page
router.get('/', function(req, res, next) {
  if (req.isAuthenticated()) {
      connection.query('SELECT * FROM addresses ORDER BY date_created DESC; SELECT count(*) as count FROM addresses',
          function (error, results, fields) {
              if (error) {
                  throw error;
              }
              res.render('addresses/index', {
                  title: 'Addresses',
                  req: req,
                  results: results,
                  alert: req.flash('alert')
              });
          }
      );
  } else {
      res.redirect('/login');
  }
});

// USER ROUTES
router.get('/users/new', isNotAuthenticated, function(req, res, next){
    res.render('users/new', {
        title: 'Sign up',
        req: req,
        errors: req.flash('errors'),
        inputs: req.flash('inputs')
    });
});

// validate user input and if wrong redirect to register page with errors and inputs else save data into
// database and redirect to login with flash message
router.post('/users', isNotAuthenticated, [
    body('email', 'Empty email.').not().isEmpty(),
    body('password', 'Empty password.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('password', 'Password must be between 5-60 characters.').isLength({min:5, max:60}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail(),
    body('password', 'Password must contain one lowercase character, one uppercase character, a number, and ' +
        'a special character.').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i")
], function(req, res, next){
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username});
        res.redirect('/users/new');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('password').trim().escape();
        sanitizeBody('username').trim().escape();
        const email = req.body.email;
        const password = req.body.password;
        const username = req.body.username;
        bcrypt.hash(password, saltRounds, function(err, hash) {
            // Store hash in your password DB.
            if (err) {
                throw error;
            }
            connection.query('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                [email, username, hash], function (error, results, fields) {
                    // error will be an Error if one occurred during the query
                    // results will contain the results of the query
                    // fields will contain information about the returned results fields (if any)
                    if (error) {
                        throw error;
                    }
                    req.flash('alert', 'You have successfully registered.');
                    res.redirect('/login');
                });
        });
    }
});

router.get('/users/:id', isResource, isAuthenticated, function(req, res){
    connection.query('SELECT id, email, username, description, imageurl, datecreated, level FROM users WHERE id = ?',
        [req.params.id],
        function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            console.log(results);
            res.render('users/show', {
                                title: 'Profile',
                                req: req,
                                results: results,
                                moment: moment,
                                alert: req.flash('alert')
                            });
        });
});

router.get('/users/:id/edit', isResource, isAuthenticated, function(req, res){
    if (req.user.id === Number(req.params.id)){
        connection.query('SELECT id, email, username, description FROM users WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('users/edit', {
                    title: 'Edit profile',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, [
    body('email', 'Empty email.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('description', 'Description must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username, description: req.body.description});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('username').trim().escape();
        sanitizeBody('description').trim().escape();
        const email = req.body.email;
        const username = req.body.username;
        const description = req.body.description;
        connection.query('UPDATE users SET email = ?, username = ?, description = ? WHERE id = ?',
            [email, username, description, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Profile edited.');
                res.redirect(req._parsedOriginalUrl.pathname);
            });
    }
});

router.delete('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, function(req, res){
    connection.query('DELETE FROM users WHERE id = ?', [req.params.id], function (error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        req.flash('alert', 'Profile deleted.');
        req.logout();
        res.redirect('/');
    });
});


// address routes
router.get('/addresses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('addresses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/addresses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
},[
            body('building_number', 'Empty building number.').not().isEmpty(),
            body('street', 'Empty street.').not().isEmpty(),
            body('city', 'Empty city.').not().isEmpty(),
            body('state', 'Empty state.').not().isEmpty(),
            body('country', 'Empty country.').not().isEmpty(),
            body('zip', 'Empty zip.').not().isEmpty(),
            body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
            body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
            body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
            body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
            body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
            body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
        ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
                state: req.body.state, country: req.body.country, zip: req.body.zip});
            res.redirect('/addresses/new');
        }
        else {
            sanitizeBody('building_number').trim().escape();
            sanitizeBody('street').trim().escape();
            sanitizeBody('city').trim().escape();
            sanitizeBody('state').trim().escape();
            sanitizeBody('country').trim().escape();
            sanitizeBody('zip').trim().escape();
            const building_number = req.body.building_number;
            const street = req.body.street;
            const city = req.body.city;
            const state = req.body.state;
            const country = req.body.country;
            const zip = req.body.zip;
            connection.query('INSERT INTO addresses (building_number, street, city, state, country, zip) VALUES ' +
                '(?, ?, ?, ?, ?, ?)', [building_number, street, city, state, country, zip], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address created.');
                res.redirect('/');
            });
        }
    }
);

router.get('/addresses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, building_number, street, city, state, country, zip FROM addresses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('addresses/edit', {
                    title: 'Edit address',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
}, [
    body('building_number', 'Empty building number.').not().isEmpty(),
    body('street', 'Empty street.').not().isEmpty(),
    body('city', 'Empty city.').not().isEmpty(),
    body('state', 'Empty state.').not().isEmpty(),
    body('country', 'Empty country.').not().isEmpty(),
    body('zip', 'Empty zip.').not().isEmpty(),
    body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
    body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
    body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
    body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
    body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
    body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
            state: req.body.state, country: req.body.country, zip: req.body.zip});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('building_number').trim().escape();
        sanitizeBody('street').trim().escape();
        sanitizeBody('city').trim().escape();
        sanitizeBody('state').trim().escape();
        sanitizeBody('country').trim().escape();
        sanitizeBody('zip').trim().escape();
        const building_number = req.body.building_number;
        const street = req.body.street;
        const city = req.body.city;
        const state = req.body.state;
        const country = req.body.country;
        const zip = req.body.zip;
        connection.query('UPDATE addresses SET building_number = ?, street = ?, city = ?, state = ?,' +
            'country = ?, zip = ? WHERE id = ?',
            [building_number, street, city, state, country, zip, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address edited.');
                res.redirect('/');
            });
    }
});

router.delete('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            connection.query('DELETE FROM addresses WHERE id = ?', [req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address deleted.');
                res.redirect('/');
            });
        } else {
            res.render('403');
        }
        });

// doctor routes
router.get('/doctors', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM doctors ORDER BY date_created DESC; SELECT count(*) as count FROM doctors',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('doctors/index', {
                    title: 'Doctors',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/doctors/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('doctors/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/doctors', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/doctors/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO doctors (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?, ?, ?, ?, ?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Doctor created.');
                res.redirect('/doctors');
            });
        }
    }
);

router.get('/doctors/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM doctors WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('doctors/edit', {
                    title: 'Edit doctor',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/doctors/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE doctors SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Doctor edited.');
                res.redirect('/doctors');
            });
    }
});

router.delete('/doctors/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM doctors WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Doctor deleted.');
            res.redirect('/doctors');
        });
    } else {
        res.render('403');
    }
});

// gender routes
router.get('/genders', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM genders ORDER BY date_created DESC; SELECT count(*) as count FROM genders',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('genders/index', {
                    title: 'Genders',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/genders/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('genders/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/genders', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('gender', 'Empty gender.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {gender: req.body.gender});
            res.redirect('/genders/new');
        }
        else {
            sanitizeBody('gender').trim().escape();
            const gender = req.body.gender;
            connection.query('INSERT INTO genders (gender) VALUES ' +
                '(?)', [gender], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender created.');
                res.redirect('/genders');
            });
        }
    }
);

router.get('/genders/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, gender FROM genders WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('genders/edit', {
                    title: 'Edit gender',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('gender', 'Empty gender.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {gender: req.body.gender});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('gender').trim().escape();
        const gender = req.body.gender;
        connection.query('UPDATE genders SET gender = ? WHERE id = ?',
            [gender, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender edited.');
                res.redirect('/genders');
            });
    }
});

router.delete('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM genders WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Gender deleted.');
            res.redirect('/genders');
        });
    } else {
        res.render('403');
    }
});

// insurance routes
router.get('/insurances', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM insurances ORDER BY date_created DESC; SELECT count(*) as count FROM insurances',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('insurances/index', {
                    title: 'Insurances',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/insurances/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('insurances/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/insurances', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('name', 'Name must be between 5-100 characters.').isLength({min:5, max:100}),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, description: req.body.description});
            res.redirect('/insurances/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            connection.query('INSERT INTO insurances (name, description) VALUES ' +
                '(?, ?)', [name, description], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Insurance created.');
                res.redirect('/insurances');
            });
        }
    }
);

router.get('/insurances/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description FROM insurances WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('insurances/edit', {
                    title: 'Edit insurance',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/insurances/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('name', 'Name must be between 5-100 characters.').isLength({min:5, max:100}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, description: req.body.description});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        connection.query('UPDATE insurances SET name = ?, description = ? WHERE id = ?',
            [name, description, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Insurance edited.');
                res.redirect('/insurances');
            });
    }
});

router.delete('/insurances/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM insurances WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Insurance deleted.');
            res.redirect('/insurances');
        });
    } else {
        res.render('403');
    }
});

// medication routes
router.get('/medications', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM medications ORDER BY date_created DESC; SELECT count(*) as count FROM medications',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('medications/index', {
                    title: 'Medications',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/medications/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('medications/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/medications', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('cost', 'Empty description.').not().isEmpty(),
        body('name', 'Name must be between 5-100 characters.').isLength({min:5, max:100}),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, description: req.body.description, cost: req.body.cost});
            res.redirect('/medications/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            sanitizeBody('cost').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            const cost = req.body.cost;
            connection.query('INSERT INTO medications (name, description, cost) VALUES ' +
                '(?, ?, ?)', [name, description, cost], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Medication created.');
                res.redirect('/medications');
            });
        }
    }
);

router.get('/medications/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description, cost FROM medications WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('medications/edit', {
                    title: 'Edit medication',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/medications/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('cost', 'Empty description.').not().isEmpty(),
    body('name', 'Name must be between 5-100 characters.').isLength({min:5, max:100}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, description: req.body.description, cost: req.body.cost});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        sanitizeBody('cost').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        const cost = req.body.cost;
        connection.query('UPDATE medications SET name = ?, description = ?, cost = ? WHERE id = ?',
            [name, description, cost, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Medication edited.');
                res.redirect('/medications');
            });
    }
});

router.delete('/medications/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM medications WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Medication deleted.');
            res.redirect('/medications');
        });
    } else {
        res.render('403');
    }
});

// patient routes
router.get('/patients', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM patients ORDER BY date_created DESC; SELECT count(*) as count FROM patients',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('patients/index', {
                    title: 'Patients',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/patients/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('patients/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/patients', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/patients/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO patients (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Patient created.');
                res.redirect('/patients');
            });
        }
    }
);

router.get('/patients/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM patients WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('patients/edit', {
                    title: 'Edit patient',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/patients/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE patients SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Patient edited.');
                res.redirect('/patients');
            });
    }
});

router.delete('/patients/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM patients WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Patient deleted.');
            res.redirect('/patients');
        });
    } else {
        res.render('403');
    }
});

// procedure routes
router.get('/procedures', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM procedures ORDER BY date_created DESC; SELECT count(*) as count FROM procedures',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('procedures/index', {
                    title: 'Procedures',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/procedures/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('procedures/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/procedures', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('cost', 'Empty description.').not().isEmpty(),
        body('name', 'Name must be between 5-100 characters.').isLength({min:5, max:100}),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, description: req.body.description, cost: req.body.cost});
            res.redirect('/procedures/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            sanitizeBody('cost').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            const cost = req.body.cost;
            connection.query('INSERT INTO procedures (name, description, cost) VALUES ' +
                '(?, ?, ?)', [name, description, cost], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Procedure created.');
                res.redirect('/procedures');
            });
        }
    }
);

router.get('/procedures/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description, cost FROM procedures WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('procedures/edit', {
                    title: 'Edit procedure',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/procedures/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('cost', 'Empty description.').not().isEmpty(),
    body('name', 'Name must be between 5-100 characters.').isLength({min:5, max:100}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, description: req.body.description, cost: req.body.cost});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        sanitizeBody('cost').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        const cost = req.body.cost;
        connection.query('UPDATE procedures SET name = ?, description = ?, cost = ? WHERE id = ?',
            [name, description, cost, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Procedure edited.');
                res.redirect('/procedures');
            });
    }
});

router.delete('/procedures/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM procedures WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Procedure deleted.');
            res.redirect('/procedures');
        });
    } else {
        res.render('403');
    }
});

// visit routes
router.get('/visits', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM visits ORDER BY date_created DESC; SELECT count(*) as count FROM visits',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('visits/index', {
                    title: 'Visits',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/visits/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('visits/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/visits', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('patient_id', 'Empty patient id.').not().isEmpty(),
        body('doctor_id', 'Empty doctor id.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {patient_id: req.body.patient_id, doctor_id: req.body.doctor_id});
            res.redirect('/visits/new');
        }
        else {
            sanitizeBody('patient_id').trim().escape();
            sanitizeBody('doctor_id').trim().escape();
            const patient_id = req.body.patient_id;
            const doctor_id = req.body.doctor_id;
            connection.query('INSERT INTO visits (patient_id, doctor_id) VALUES ' +
                '(?, ?)', [patient_id, doctor_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Visit created.');
                res.redirect('/visits');
            });
        }
    }
);

router.get('/visits/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, patient_id, doctor_id FROM visits WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('visits/edit', {
                    title: 'Edit visit',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/visits/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('patient_id', 'Empty patient id.').not().isEmpty(),
    body('doctor_id', 'Empty doctor id.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {patient_id: req.body.patient_id, doctor_id: req.body.doctor_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('patient_id').trim().escape();
        sanitizeBody('doctor_id').trim().escape();
        const patient_id = req.body.patient_id;
        const doctor_id = req.body.doctor_id;
        connection.query('UPDATE visits SET patient_id = ?, doctor_id = ? WHERE id = ?',
            [patient_id, doctor_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Visit edited.');
                res.redirect('/visits');
            });
    }
});

router.delete('/visits/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM visits WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Visit deleted.');
            res.redirect('/visits');
        });
    } else {
        res.render('403');
    }
});

// visitmedication routes
router.get('/visitsmedications', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM visitsmedications ORDER BY date_created DESC; SELECT count(*) as count FROM visitsmedications',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('visitsmedications/index', {
                    title: 'Visitsmedications',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/visitsmedications/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('visitsmedications/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/visitsmedications', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('visit_id', 'Empty visit id.').not().isEmpty(),
        body('medication_id', 'Empty medication id.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {visit_id: req.body.visit_id, medication_id: req.body.medication_id});
            res.redirect('/visitsmedications/new');
        }
        else {
            sanitizeBody('visit_id').trim().escape();
            sanitizeBody('medication_id').trim().escape();
            const visit_id = req.body.visit_id;
            const medication_id = req.body.medication_id;
            connection.query('INSERT INTO visitsmedications (visit_id, medication_id) VALUES ' +
                '(?, ?)', [visit_id, medication_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Visitmedication created.');
                res.redirect('/visitsmedications');
            });
        }
    }
);

router.get('/visitsmedications/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, visit_id, medication_id FROM visitsmedications WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('visitsmedications/edit', {
                    title: 'Edit visitmedication',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/visitsmedications/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('visit_id', 'Empty visit id.').not().isEmpty(),
    body('medication_id', 'Empty medication id.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {visit_id: req.body.visit_id, medication_id: req.body.medication_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('visit_id').trim().escape();
        sanitizeBody('medication_id').trim().escape();
        const visit_id = req.body.visit_id;
        const medication_id = req.body.medication_id;
        connection.query('UPDATE visitsmedications SET visit_id = ?, medication_id = ? WHERE id = ?',
            [visit_id, medication_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Visitmedication edited.');
                res.redirect('/visitsmedications');
            });
    }
});

router.delete('/visitsmedications/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM visitsmedications WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Visitmedication deleted.');
            res.redirect('/visitsmedications');
        });
    } else {
        res.render('403');
    }
});

// visitprocedure routes
router.get('/visitsprocedures', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM visitsprocedures ORDER BY date_created DESC; SELECT count(*) as count FROM visitsprocedures',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('visitsprocedures/index', {
                    title: 'Visitsprocedures',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/visitsprocedures/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('visitsprocedures/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/visitsprocedures', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('visit_id', 'Empty visit id.').not().isEmpty(),
        body('procedure_id', 'Empty procedure id.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {visit_id: req.body.visit_id, procedure_id: req.body.procedure_id});
            res.redirect('/visitsprocedures/new');
        }
        else {
            sanitizeBody('visit_id').trim().escape();
            sanitizeBody('procedure_id').trim().escape();
            const visit_id = req.body.visit_id;
            const procedure_id = req.body.procedure_id;
            connection.query('INSERT INTO visitsprocedures (visit_id, procedure_id) VALUES ' +
                '(?, ?)', [visit_id, procedure_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Visitprocedure created.');
                res.redirect('/visitsprocedures');
            });
        }
    }
);

router.get('/visitsprocedures/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, visit_id, procedure_id FROM visitsprocedures WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('visitsprocedures/edit', {
                    title: 'Edit visitprocedure',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/visitsprocedures/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('visit_id', 'Empty visit id.').not().isEmpty(),
    body('procedure_id', 'Empty procedure id.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {visit_id: req.body.visit_id, procedure_id: req.body.procedure_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('visit_id').trim().escape();
        sanitizeBody('procedure_id').trim().escape();
        const visit_id = req.body.visit_id;
        const procedure_id = req.body.procedure_id;
        connection.query('UPDATE visitsprocedures SET visit_id = ?, procedure_id = ? WHERE id = ?',
            [visit_id, procedure_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Visitprocedure edited.');
                res.redirect('/visitsprocedures');
            });
    }
});

router.delete('/visitsprocedures/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM visitsprocedures WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Visitprocedure deleted.');
            res.redirect('/visitsprocedures');
        });
    } else {
        res.render('403');
    }
});

router.get('/login', isNotAuthenticated, function(req, res, next){
    res.render('login', {
        title: 'Log in',
        req: req,
        errors: req.flash('errors'),
        input: req.flash('input'),
        alert: req.flash('alert')
    });
});

router.post('/login', isNotAuthenticated, passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    })
);

router.get('/logout', isAuthenticated, function(req, res){
    req.logout();
    res.redirect('/login');
});

module.exports = router;
