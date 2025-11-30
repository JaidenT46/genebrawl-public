import {ChatStreamEntry} from "./entries/ChatStreamEntry";
import {StreamEntry} from "./entries/StreamEntry";

export class StreamEntryFactory {
    static createStreamEntryByType(instance: NativePointer) {
        const type = StreamEntry.getStreamEntryType(instance);
        
        switch(type) {
            case 2:
                return new ChatStreamEntry(instance);
            default:
                return new StreamEntry(instance);
        }
    }
}