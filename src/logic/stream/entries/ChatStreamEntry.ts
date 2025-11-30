import {StreamEntry} from "./StreamEntry";

const messageOffset = 48;

export class ChatStreamEntry extends StreamEntry {
    getMessage() {
        return this.instance.add(messageOffset).readPointer().fromsc();
    }

    setMessage(message: string) {
        this.instance.add(messageOffset).readPointer().scptr(message);
    }
}