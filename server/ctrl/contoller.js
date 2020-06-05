const bcrypt = require('bcryptjs')

module.exports = {
    signup: async (req, res) => {
        const {email, password} = req.body
        const  db = req.app.get('db')
        const existingUser = await db.check_user_exists([email])
        if(existingUser[0]){
            return res.status(404).send(`Email already exists`)
        }

        const salt  = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        let createdUser = await db.create_user({email, hash})
        req.session.user = {id: createdUser[0].id, email: createdUser[0].email}
        res.status(200).send(req.session.user)
    },
    login: async (req, res) => {
        const {email, password}
        const db = req.app.get('db')
        const existingUser = db.check_user_exists(email)

        if(!existingUser[0]){
            res.status(404).send('Please try again')
        }
        let result = bcrypt.compareSync(password, existingUser[0].user_password)
        if(result){
            req.session.user = {id: existingUser[0].id, email: existingUser[0].email}
            res.status(200).send(req.session.user)
        } else {
            return res.status(401).send('Incorrect email/password')
        }
    }
}