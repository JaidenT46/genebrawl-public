export class DebugHudMessageCollector {
    private messages: Array<string>;

    constructor() {
        this.messages = [];
    }

    addMessage(message: string) {
        this.messages.push(message);
    }

    combineMessageLinesToString() {
        return this.messages.join("\n");
    }

    getMessageCount() {
        return this.messages.length;
    }

    getMessage(index: number) {
        if (index > this.getMessageCount()) {
            console.log("DebugHudMessageCollector::getMessage", "Message", index, "is NULL!");
            return null;
        }

        return this.messages[index];
    }

    setMessages(messages: Array<string>) {
        this.messages = messages;
    }

    getMessages() {
        return this.messages;
    }

    clone() {
        const messageCollector = new DebugHudMessageCollector();

        messageCollector.setMessages(this.messages);

        return messageCollector;
    }
}