# FP LUA Sessions

Creates a `res.locals.session` object or calls next(err) if no session is there.

Usage:

```
import { resolveSession } from "fp-lua-sessions";

app.get("/some_endpoint", resolveSession, (req, res, next) =>  {
    console.log(res.locals.session)
    res.send("OK")
}
```

or

```
import { resolveSession } from "fp-lua-sessions";

app.use(resolveSession);
```