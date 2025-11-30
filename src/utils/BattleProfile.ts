
export class BattleProfile {
    playerId: number[];
    hero: number;
    player: NativePointer;

    constructor(playerId: number[], hero: number, player: NativePointer) {
        this.playerId = playerId;
        this.hero = hero;
        this.player = player;
    }
}
