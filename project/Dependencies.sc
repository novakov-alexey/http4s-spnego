import mill._
import mill.scalalib._

object Dependencies {
  lazy val http4sVersion = "0.23.27"    
  lazy val http4sBase = {
    Agg(ivy"org.http4s::blaze-core:0.23.16", ivy"org.http4s::http4s-blaze-server:0.23.16")
  }
  lazy val http4sDsl = Agg(ivy"org.http4s::http4s-dsl:$http4sVersion")

  lazy val logging = Agg(ivy"org.typelevel::log4cats-slf4j:2.7.0", ivy"ch.qos.logback:logback-classic:1.2.3")

  lazy val kindProjector = Agg(ivy"org.typelevel:kind-projector_2.13.5:0.11.3") // had to put explicit Scala version, otherwise it resolves some old/wrong Scala version :-(

  lazy val tests = Agg(ivy"org.scalatest::scalatest:3.2.18") ++ http4sDsl
}
