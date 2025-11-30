import {PiranhaMessage} from "../PiranhaMessage";

const errorCodeOffset = 144;
const redirectDomainOffset = 168;
const reasonOffset = 192;
const updateUrlOffset = 184;
const unknownOffset = 201; // i don't know what's this, I assume that it's something like "shouldWipeKeychain", please change the name for it <3 

export class LoginFailedMessage extends PiranhaMessage {
    getErrorCode(): number {
        return this.instance.add(errorCodeOffset).readInt();
    }

    getRedirectDomain(): string {
        return this.instance.add(redirectDomainOffset).readPointer().fromsc();
    }

    getReason(): string {
        return this.instance.add(reasonOffset).readPointer().fromsc();
    }

    getUpdateURL(): string {
        return this.instance.add(updateUrlOffset).readPointer().fromsc();
    }

    setErrorCode(errorCode: number) {
        this.instance.add(errorCodeOffset).writeInt(errorCode);
    }

    setRedirectDomain(domain: string) {
        this.instance.add(redirectDomainOffset).writePointer(domain.scptr());
    }

    setReason(reason: string) {
        this.instance.add(reasonOffset).writePointer(reason.scptr());
    }

    setUpdateURL(url: string) {
        this.instance.add(updateUrlOffset).writePointer(url.scptr());
    }

    setUnknown(value: number) {
        this.instance.add(unknownOffset).writeU8(value);
    }
}