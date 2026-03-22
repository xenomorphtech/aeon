use crate::il::Stmt;
use bevy_ecs::component::Component;

#[derive(Component, Debug, Clone)]
pub struct Address(pub u64);

#[derive(Component, Debug, Clone)]
pub struct RawInstruction(pub String);

#[derive(Component, Debug, Clone)]
pub struct LiftedIL(pub Stmt);

#[derive(Component, Debug, Clone)]
pub struct BelongsToFunction(pub u64);

#[derive(Component, Debug, Clone)]
pub struct CfgEdges(pub Vec<u64>);
