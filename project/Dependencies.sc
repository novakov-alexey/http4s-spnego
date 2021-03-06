import mill._
import mill.scalalib._

object Dependencies {
  lazy val http4sVersion = "0.21.19"    
  lazy val http4sBase = {
    Agg(ivy"org.http4s::http4s-core:$http4sVersion", ivy"org.http4s::http4s-blaze-server:$http4sVersion")
  }
  lazy val http4sDsl = Agg(ivy"org.http4s::http4s-dsl:$http4sVersion")

  lazy val logging = Agg(ivy"io.chrisdavenport::log4cats-slf4j:1.1.1", ivy"ch.qos.logback:logback-classic:1.2.3")

  lazy val kindProjector = Agg(ivy"org.typelevel:kind-projector_2.13.5:0.11.3") // had to put explicit Scala version, otherwise it resolves some old/wrong Scala version :-(

  lazy val betterMonadicFor = Agg(ivy"com.olegpy::better-monadic-for:0.3.1")

  lazy val tests = Agg(ivy"org.scalatest::scalatest:3.2.5") ++ http4sDsl
}
