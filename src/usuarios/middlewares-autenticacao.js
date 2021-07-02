const passport = require('passport');

module.exports = {
    local:  (req, res, next) => {
        passport.authenticate(
            'local', 
            {session: false},
            (erro, usuario, info) => {
                // Status 401 referente as credenciais inseridas
                if (erro && erro.name === 'InvalidArgumentError'){
                    return res.status(401).json({ erro: erro.message });
                }

                // Status 500 referente a um erro nao tratavel pelo servidor
                if (erro) {
                    return res.status(500).json({ erro: erro.message});
                }

                // Erro de credencial quando usuario nao preenche nenhum campo, por ex
                if (!usuario){
                    return res.status(401).json();
                }

                req.user = usuario;
                return next();
            }
        )(req, res, next);
    }
}