import {GUI} from "../../titan/flash/gui/GUI";
import {Libg} from "../../libs/Libg";
import {MessageManager} from "../../laser/client/network/MessageManager";
import {TeamChatMessage} from "../../logic/message/team/TeamChatMessage";
import {LocalizationManager} from "../../gene/localization/index";


export const TeamChatMessage_encode = new NativeFunction( // 14049 below ctor
    Libg.offset(0x970C64, 0x47DFB8), 'void', ['pointer']
);

export class TeamSpam {
    private static encodeListener: InvocationListener | undefined;
    private static spamInterval: NodeJS.Timeout | undefined;
    private static spamText: string;

    static start() {
        if (!TeamSpam.encodeListener) {
            GUI.showFloaterText(LocalizationManager.getString("TEAM_SPAM_INIT"));

            TeamSpam.encodeListener = Interceptor.attach(TeamChatMessage_encode, {
                onEnter(args) {
                    TeamSpam.encodeListener!.detach();
                    TeamSpam.encodeListener = undefined;

                    TeamSpam.spamText = args[0].add(TeamChatMessage.messageOffset).fromsc();

                    setTimeout(function () {
                        TeamSpam.spamInterval = setInterval(function () {
                            const message = new TeamChatMessage();
                            message.setMessage(TeamSpam.spamText);
                            MessageManager.sendMessage(message);
                        }, 50);
                    }, 200);
                }
            });
        }
    }

    static end() {
        if (!TeamSpam.spamInterval && !TeamSpam.encodeListener) {
            GUI.showFloaterText(LocalizationManager.getString("TEAM_SPAM_NOT_RUNNING"));
            return;
        }

        if (TeamSpam.spamInterval) {
            clearInterval(TeamSpam.spamInterval);
            TeamSpam.spamInterval = undefined;
            GUI.showFloaterText(LocalizationManager.getString("TEAM_SPAM_STOPPED"));
        }

        if (TeamSpam.encodeListener) {
            TeamSpam.encodeListener.detach();
            TeamSpam.encodeListener = undefined;
            GUI.showFloaterText(LocalizationManager.getString("TEAM_SPAM_CANCELLED"));
        }
    }
}