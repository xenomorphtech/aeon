use bevy_ecs::component::Component;
use crate::il::Stmt;

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

#[derive(Component, Debug, Clone)]
pub struct AnalysisName(pub String);
