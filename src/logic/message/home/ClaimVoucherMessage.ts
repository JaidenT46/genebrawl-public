import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";
import {PiranhaMessage} from "../PiranhaMessage";

const voucherCodeOffset = 144;

export class ClaimVoucherMessage extends PiranhaMessage {
    constructor(code: string) {
        super(
            LogicLaserMessageFactory.createMessage(17683)
        );

        this.instance.add(voucherCodeOffset).scptr(code);
    }
}