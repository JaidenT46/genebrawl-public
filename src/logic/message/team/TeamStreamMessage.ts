import {StreamEntryFactory} from "../../stream/StreamEntryFactory";
import {LogicLaserMessageFactory} from "../LogicLaserMessageFactory";
import {PiranhaMessage} from "../PiranhaMessage";

const streamEntryArrayOffset = 152;

export class TeamStreamMessage extends PiranhaMessage {
    constructor(instance?: NativePointer) {
        if (!instance) {
            instance = LogicLaserMessageFactory.createMessage(24131);
        }

        super(instance);
    }

    getStreamEntryArray() {
        return this.instance.add(streamEntryArrayOffset).readPointer();
    }

    setStreamEntryArray(array: NativePointer) {
        return this.instance.add(streamEntryArrayOffset).writePointer(array);
    }

    getStreamLength() {
        return this.getStreamEntryArray().add(12).readInt();
    }

    getStreamEntryByIndex(index: number) {
        const instance = this.getStreamEntryArray().add(Process.pointerSize * index).readPointer().readPointer();

        return StreamEntryFactory.createStreamEntryByType(instance);
    }
}