import IHeader from "./Interfaces/IHeader";
import IPayload from "./Interfaces/IPayload";
import crypto from 'crypto';

class JWT {
    private secretOrPrivateKey: string;

    constructor(secretPrivKey: string) {
        this.secretOrPrivateKey = secretPrivKey;
    }

    public generateToken(payload: IPayload, header: IHeader): string {
        if (!payload || !header) {
            console.error('Payload or header missing');
            return '';
        }

        try {
            const token: string = [
                Buffer.from(JSON.stringify(header)).toString("base64"),
                Buffer.from(JSON.stringify(payload)).toString("base64")
            ].join(".");

            const privateKeyHmac: crypto.Hmac = crypto.createHmac("sha256", this.secretOrPrivateKey);
            const signature = privateKeyHmac.update(token).digest("base64");

            return [token, signature].join(".");
        } catch (error : any) {
            console.error('Error generating token:', error?.message);
            return '';
        }
    }

    decodeToken(token: string): { header: IHeader | null, payload: IPayload | null } {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                console.error('Invalid JWT format');
                return { header: null, payload: null };
            }

            const header: IHeader = JSON.parse(Buffer.from(parts[0], "base64").toString());
            const payload: IPayload = JSON.parse(Buffer.from(parts[1], "base64").toString());
            return { header, payload };
        } catch (error : any) {
            console.error('Error decoding JWT:', error?.message);
            return { header: null, payload: null };
        }
    }

    verifyToken(token: string): boolean {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                console.error('Invalid JWT format');
                return false;
            }

            const [header, payload, signature] = parts;
            const privateKeyHmac: crypto.Hmac = crypto.createHmac("sha256", this.secretOrPrivateKey);
            const expectedSignature = privateKeyHmac.update([header, payload].join(".")).digest("base64");

            return signature === expectedSignature;
        } catch (error : any) {
            console.error('Error verifying token:', error?.message);
            return false;
        }
    }
}

const IstanceJWT: JWT = new JWT("SECRET");
const payload: IPayload = {
    iat: "io",
    sub: "io",
    name: "musijwt"
}
const header: IHeader = {
    alg: "sha256",
    typ: "JWT"
}

const token: string = IstanceJWT.generateToken(payload, header);
console.log(token);

const decode: { header: IHeader | null, payload: IPayload | null } = IstanceJWT.decodeToken(token);
console.log(decode);

const verify = IstanceJWT.verifyToken(token);
console.log(verify);
